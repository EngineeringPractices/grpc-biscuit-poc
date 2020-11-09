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
	fields := msg.Descriptor().Fields()
	out := make(map[biscuit.String]biscuit.Atom)
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)

		var elts map[interface{}]protoreflect.Value
		var fieldName func(key interface{}) string
		switch {
		case field.IsList():
			list := msg.Get(field).List()
			elts = make(map[interface{}]protoreflect.Value, list.Len())
			for i := 0; i < list.Len(); i++ {
				elts[i] = list.Get(i)
			}
			fieldName = func(key interface{}) string {
				return fmt.Sprintf("%s.%d", field.Name(), key)
			}
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
				if elt.Bool() {
					out[biscuit.String(fieldName(key))] = biscuit.Integer(1)
				} else {
					out[biscuit.String(fieldName(key))] = biscuit.Integer(0)
				}
			case protoreflect.EnumKind:
				// swap the enum value to its name from the definition
				// and use it as a string on biscuit side
				out[biscuit.String(fieldName(key))] = biscuit.String(field.Enum().Values().ByNumber(elt.Enum()).Name())
			case protoreflect.Int32Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Sint32Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Uint32Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Uint())
			case protoreflect.Int64Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Sint64Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Uint64Kind:
				if elt.Uint() > math.MaxInt64 {
					v.logger.Warn("uint64 field does not fit in int64", zap.String("field", fieldName(key)))
					continue
				}
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Sfixed32Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Fixed32Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Uint())
			case protoreflect.FloatKind:
				v.logger.Warn("float field is not supported", zap.String("field", fieldName(key)))
			case protoreflect.Sfixed64Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Fixed64Kind:
				if elt.Uint() > math.MaxInt64 {
					v.logger.Warn("uint64 field does not fit in int64", zap.String("field", fieldName(key)))
					continue
				}
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.DoubleKind:
				v.logger.Warn("double field is not supported", zap.String("field", fieldName(key)))
			case protoreflect.StringKind:
				out[biscuit.String(fieldName(key))] = biscuit.String(elt.String())
			case protoreflect.BytesKind:
				out[biscuit.String(fieldName(key))] = biscuit.Bytes(elt.Bytes())
			case protoreflect.MessageKind:
				switch elt.Message().Descriptor().FullName() {
				case "google.protobuf.Timestamp":
					ts := elt.Message().Interface().(*timestamppb.Timestamp)
					out[biscuit.String(fieldName(key))] = biscuit.Date(ts.AsTime())
				default:
					// recurse until we only get basic types
					// concatenating sub field name with parent field name
					subout := v.flattenProtoMessage(elt.Message())
					for k, v := range subout {
						name := fmt.Sprintf("%s.%s", fieldName(key), string(k))
						out[biscuit.String(name)] = v
					}
				}
			case protoreflect.GroupKind: // deprecated proto2 feature
				v.logger.Warn("group field is not supported", zap.String("field", fieldName(key)))
			default:
				v.logger.Warn("unsupported proto kind",
					zap.String("field", fieldName(key)),
					zap.String("kind", field.Kind().String()),
				)
			}
		}
	}
	return out
}
