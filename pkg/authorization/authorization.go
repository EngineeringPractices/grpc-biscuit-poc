package authorization

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
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
	logger *log.Logger
	pubkey sig.PublicKey
}

func NewBiscuitInterceptor(rootPubKey []byte, logger *log.Logger) (BiscuitInterceptor, error) {
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
	i.logger.Printf("unary interceptor %s %T", info.FullMethod, req)

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
	i.logger.Printf("stream interceptor %s", info.FullMethod)

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
	logger *log.Logger
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

		var err error
		fields, err = flattenProtoMessage(protoMsg.ProtoReflect())
		if err != nil {
			return err
		}
	}

	var debugFacts []string
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

	if err := v.Verify(); err != nil {
		v.logger.Println("---------------------------------------------------------")
		v.logger.Printf("access denied: %s\n", err)
		v.logger.Printf("verifier world: %s\n", v.PrintWorld())
		v.logger.Println("ambient facts:")
		for _, f := range debugFacts {
			v.logger.Printf("\t%s\n", f)
		}
		v.logger.Println("---------------------------------------------------------")
		return ErrNotAuthorized
	}

	return nil
}

func flattenProtoMessage(msg protoreflect.Message) (map[biscuit.String]biscuit.Atom, error) {
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
		case field.IsExtension():
			// TODO ???
		default:
			elts = map[interface{}]protoreflect.Value{struct{}{}: msg.Get(field)}
			fieldName = func(key interface{}) string {
				return string(field.Name())
			}
		}

		for key, elt := range elts {
			switch field.Kind() {
			case protoreflect.BoolKind: // TODO (bool)
			case protoreflect.EnumKind:
				// swap the enum value to its name from the definition
				// and use it as a string on biscuit side
				out[biscuit.String(fieldName(key))] = biscuit.String(field.Enum().Values().ByNumber(elt.Enum()).Name())
			case protoreflect.Int32Kind: // TODO (int32)
			case protoreflect.Sint32Kind: // TODO (int32)
			case protoreflect.Uint32Kind: // TODO (uint32)
			case protoreflect.Int64Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Sint64Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Uint64Kind: // TODO (uint64)
			case protoreflect.Sfixed32Kind: // TODO (int32)
			case protoreflect.Fixed32Kind: // TODO (uint32)
			case protoreflect.FloatKind: // TODO (float32)
			case protoreflect.Sfixed64Kind:
				out[biscuit.String(fieldName(key))] = biscuit.Integer(elt.Int())
			case protoreflect.Fixed64Kind: // TODO (uint64)
			case protoreflect.DoubleKind: // TODO (float64)
			case protoreflect.StringKind:
				out[biscuit.String(fieldName(key))] = biscuit.String(elt.String())
			case protoreflect.BytesKind:
				out[biscuit.String(fieldName(key))] = biscuit.Bytes(elt.Bytes())
			case protoreflect.MessageKind:
				//
				switch elt.Message().Descriptor().FullName() {
				case "google.protobuf.Timestamp":
					ts := elt.Message().Interface().(*timestamppb.Timestamp)
					out[biscuit.String(fieldName(key))] = biscuit.Date(ts.AsTime())
				default:
					// recurse until we get basic type only
					subout, err := flattenProtoMessage(elt.Message())
					if err != nil {
						return nil, err
					}
					for k, v := range subout {
						name := fmt.Sprintf("%s.%s", fieldName(key), string(k))
						out[biscuit.String(name)] = v
					}
				}

			case protoreflect.GroupKind: // deprecated
				return nil, fmt.Errorf("authorization: unsupported protoreflect kind: %v", field.Kind())
			default:
				return nil, fmt.Errorf("authorization: unsupported protoreflect kind: %v", field.Kind())
			}
		}
	}
	return out, nil
}
