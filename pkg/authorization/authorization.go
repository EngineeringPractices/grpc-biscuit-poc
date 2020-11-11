package authorization

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/biscuit-go/sig"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrNotAuthorized = status.Error(codes.PermissionDenied, "not authorized")

const MetadataAuthorization = "authorization"

type BiscuitInterceptor interface {
	Unary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error)
	Stream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error
}

type biscuitInterceptor struct {
	logger *zap.Logger
	pubkey sig.PublicKey
}

func NewBiscuitInterceptor(rootPubKey []byte, logger *zap.Logger) (BiscuitInterceptor, error) {
	pubkey, err := sig.NewPublicKey(rootPubKey)
	if err != nil {
		return nil, err
	}

	return &biscuitInterceptor{
		logger: logger,
		pubkey: pubkey,
	}, nil
}

func (i *biscuitInterceptor) Unary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	verifier, err := i.newVerifierFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := verifier.verify(info.FullMethod, req); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func (i *biscuitInterceptor) Stream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	verifier, err := i.newVerifierFromCtx(ss.Context())
	if err != nil {
		return err
	}

	if err := verifier.verify(info.FullMethod, nil); err != nil {
		return err
	}
	return handler(srv, ss)
}

type grpcVerifier struct {
	biscuit.Verifier
	logger *zap.Logger
}

func (i *biscuitInterceptor) newVerifierFromCtx(ctx context.Context) (*grpcVerifier, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("authorization: failed to retrieve context metadata")
	}

	token, ok := md[MetadataAuthorization]
	if !ok {
		return nil, fmt.Errorf("authorization: missing required context metadata %q", MetadataAuthorization)
	}
	tokenBytes, err := base64.URLEncoding.DecodeString(token[0])
	if err != nil {
		return nil, err
	}
	b, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		return nil, err
	}

	verifier, err := b.Verify(i.pubkey)
	if err != nil {
		return nil, err
	}

	return &grpcVerifier{
		Verifier: verifier,
		logger:   i.logger,
	}, nil
}

func (v *grpcVerifier) verify(methodName string, req interface{}) error {
	var fields map[biscuit.String]biscuit.Atom

	if req != nil {
		protoMsg, ok := req.(proto.Message)
		if !ok {
			return errors.New("authorization: invalid request")
		}

		fields = v.flattenProtoMessage(protoMsg.ProtoReflect())
	}

	debugFacts := make([]string, 0, len(fields)+1)
	// Add request method and arguments to the verifier
	methodFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "method",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String(methodName)},
	}}
	v.AddFact(methodFact)
	debugFacts = append(debugFacts, methodFact.String())

	for name, value := range fields {
		argFact := biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "arg",
			IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), name, value},
		}}
		v.AddFact(argFact)
		debugFacts = append(debugFacts, argFact.String())
	}
	v.logger.Debug("flattened proto request", zap.Strings("facts", debugFacts))

	audiencePubKeyBytes, err := ioutil.ReadFile("./audience.public.demo.key")
	if err != nil {
		return err
	}
	audiencePubKey, err := x509.ParsePKIXPublicKey(audiencePubKeyBytes)
	if err != nil {
		return err
	}

	var signatureMetas *signedbiscuit.UserSignatureMetadata
	v.Verifier, signatureMetas, err = signedbiscuit.WithSignatureVerification(v.Verifier, "http://audience.local", audiencePubKey.(*ecdsa.PublicKey))
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	if err := v.Verify(); err != nil {
		v.logger.Warn("failed to verify biscuit",
			zap.Error(err),
			zap.String("world", v.PrintWorld()),
			zap.Strings("ambient-facts", debugFacts),
		)
		return ErrNotAuthorized
	}

	v.logger.Info(
		"success verifying signed biscuit",
		zap.String("userID", signatureMetas.UserID),
		zap.String("userEmail", signatureMetas.UserEmail),
		zap.String("issueTime", signatureMetas.IssueTime.String()),
		zap.String("signatureTimestamp", signatureMetas.UserSignatureTimestamp.String()),
		zap.Binary("signatureNonce", signatureMetas.UserSignatureNonce),
	)

	return nil
}

func (v *grpcVerifier) flattenProtoMessage(msg protoreflect.Message) map[biscuit.String]biscuit.Atom {
	out := make(flattenedMessage)

	fields := msg.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)

		var elts map[interface{}]protoreflect.Value
		var fieldName func(key interface{}) string

		switch {
		case field.IsMap():
			m := msg.Get(field).Map()
			elts = make(map[interface{}]protoreflect.Value, m.Len())
			m.Range(func(mk protoreflect.MapKey, v protoreflect.Value) bool {
				elts[mk.Interface()] = v
				return true
			})
			fieldName = func(key interface{}) string {
				return fmt.Sprintf("%s.%v", field.Name(), key)
			}
		default:
			elts = map[interface{}]protoreflect.Value{struct{}{}: msg.Get(field)}
			fieldName = func(key interface{}) string {
				return string(field.Name())
			}
		}

		for key, elt := range elts {
			switch field.Kind() {
			case protoreflect.BoolKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					if e.Bool() {
						out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(1))
					} else {
						out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(0))
					}
				})
			case protoreflect.EnumKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					// swap the enum value to its name from the definition and use it as a string on biscuit side
					out.Insert(biscuit.String(fieldName(key)), biscuit.String(field.Enum().Values().ByNumber(e.Enum()).Name()))
				})
			case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind, protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(e.Int()))
				})
			case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(e.Int()))
				})
			case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					if e.Uint() > math.MaxInt64 {
						v.logger.Warn("uint64 field does not fit in int64", zap.String("field", fieldName(key)))
						return
					}
					out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(e.Int()))
				})
			case protoreflect.StringKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.String(e.String()))
				})
			case protoreflect.BytesKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.Bytes(e.Bytes()))
				})
			case protoreflect.MessageKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					switch e.Message().Descriptor().FullName() {
					case "google.protobuf.Timestamp":
						ts := e.Message().Interface().(*timestamppb.Timestamp)
						out.Insert(biscuit.String(fieldName(key)), biscuit.Date(ts.AsTime()))
					default:
						// recurse until we only get basic types concatenating sub field name with parent field name
						subout := v.flattenProtoMessage(e.Message())
						for k, v := range subout {
							name := fmt.Sprintf("%s.%s", fieldName(key), string(k))
							out.Insert(biscuit.String(name), v)
						}
					}
				})
			default:
				// Float, Double, Group...
				v.logger.Warn("unsupported proto kind",
					zap.String("field", fieldName(key)),
					zap.String("kind", field.Kind().String()),
				)
			}
		}
	}

	return out
}

type flattenedMessage map[biscuit.String]biscuit.Atom

// Insert add the value to the map, at key index. If a value with this key already exists, it will create a
// biscuit.List and add the original and new values to it. Other inserts at this key will keep appending to the list.
// When the key doesn't exists, the original value is stored in the map.
func (f flattenedMessage) Insert(key biscuit.String, value biscuit.Atom) {
	if v, keyExists := f[key]; keyExists {
		if l, isList := v.(biscuit.List); isList {
			f[key] = append(l, value)
		} else {
			f[key] = biscuit.List{v, value}
		}

		return
	}

	f[key] = value
}

// valuesIterator calls cb for every field values (once for regular types, N for repeated types)
func valuesIterator(field protoreflect.FieldDescriptor, element protoreflect.Value, cb func(e protoreflect.Value)) {
	if field.IsList() {
		list := element.List()
		for i := 0; i < list.Len(); i++ {
			cb(list.Get(i))
		}
		return
	}

	cb(element)
}
