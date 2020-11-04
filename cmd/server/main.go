package main

import (
	"context"
	"demo/pkg/pb"
	"demo/pkg/pb/demoerr"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type demoServer struct {
	pb.UnimplementedDemoServer
}

var _ pb.DemoServer = (*demoServer)(nil)

func (d *demoServer) Status(_ context.Context, _ *pb.StatusRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Create(_ context.Context, _ *pb.CreateRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Read(_ context.Context, _ *pb.ReadRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Update(_ context.Context, _ *pb.UpdateRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Delete(_ context.Context, _ *pb.DeleteRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func authzInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	fmt.Printf("authzInterceptorFunc %s %T\n", info.FullMethod, req)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, err
	}

	token, ok := md["authorization"]
	if !ok {
		return nil, errors.New("missing authorization")
	}
	tokenBytes, err := base64.URLEncoding.DecodeString(token[0])
	if err != nil {
		return nil, err
	}
	b, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		return nil, err
	}

	pk, err := ioutil.ReadFile("./public.demo.key")
	if err != nil {
		return nil, err
	}
	rootPubKey, err := sig.NewPublicKey(pk)
	if err != nil {
		return nil, err
	}

	verifier, err := b.Verify(rootPubKey)
	if err != nil {
		return nil, err
	}

	protoMsg, ok := req.(proto.Message)
	if !ok {
		return nil, errors.New("not a proto message")
	}

	fields, err := flattenProtoMessage(protoMsg.ProtoReflect())
	if err != nil {
		return nil, err
	}

	var debugFacts []string
	// Add request method and arguments to the verifier
	methodFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "method",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String(info.FullMethod)},
	}}
	verifier.AddFact(methodFact)
	debugFacts = append(debugFacts, methodFact.String())

	for name, value := range fields {
		argFact := biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "arg",
			IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), name, value},
		}}
		verifier.AddFact(argFact)
		debugFacts = append(debugFacts, argFact.String())
	}

	if err := verifier.Verify(); err != nil {
		fmt.Println("---------------------------------------------------------")
		fmt.Printf("Access denied: %s\n", err)
		fmt.Printf("Verifier world: %s\n", verifier.PrintWorld())
		fmt.Println("Ambient facts:")
		for _, f := range debugFacts {
			fmt.Printf("\t%s\n", f)
		}
		fmt.Println("---------------------------------------------------------")
		return nil, demoerr.ErrNotAuthorized
	}

	return handler(ctx, req)
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
			fmt.Printf("%s is extension\n", field.Name())
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
				return nil, fmt.Errorf("unsupported protoreflect kind: %v", field.Kind())
			default:
				return nil, fmt.Errorf("unsupported protoreflect kind: %v", field.Kind())
			}
		}
	}
	return out, nil
}

func main() {
	lis, err := net.Listen("tcp", "localhost:8888")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	var opts []grpc.ServerOption
	opts = append(opts, grpc.UnaryInterceptor(authzInterceptorFunc))
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterDemoServer(grpcServer, &demoServer{})

	fmt.Println("server listening on localhost:8888")
	if err := grpcServer.Serve(lis); err != nil {
		panic(err)
	}
}
