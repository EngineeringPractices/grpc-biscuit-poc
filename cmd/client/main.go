package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"demo/pkg/authorization"
	"demo/pkg/pb"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/biscuit-go/parser"
	"github.com/flynn/biscuit-go/sig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var caveats = []string{
	// require an authority allow_method fact to have been generated
	`*authorized() <- allow_method(#authority, $0)`,
}

var adminPolicy = []string{
	// allow Create, Read, Update, Delete with no conditions
	`*allow_method($0)
	<-	method(#ambient, $0)
	@ 	$0 in ["/demo.api.v1.Demo/Create", "/demo.api.v1.Demo/Read", "/demo.api.v1.Demo/Update", "/demo.api.v1.Demo/Delete"]`,
}

var developerPolicy = []string{
	// allow Create, Delete if env is dev
	`*allow_method($0)
		<-	method(#ambient, $0), 
			arg(#ambient, $1, $2) 
		@ 	$0 in ["/demo.api.v1.Demo/Create", "/demo.api.v1.Demo/Delete"], 
			$1 == "env", 
			$2 == "DEV"`,
	// allow Read and Update in dev or staging
	`*allow_method($0)
		<-	method(#ambient, $0),
			arg(#ambient, $1, $2)
		@ 	$0 in ["/demo.api.v1.Demo/Read", "/demo.api.v1.Demo/Update"],
			$1 == "env",
			$2 in ["DEV", "STG"]`,
}

var guestPolicy = []string{
	// allow Status with no conditions
	`*allow_method($0)
		<-	method(#ambient, $0) 
		@ 	$0 == "/demo.api.v1.Demo/Status"`,
}

var attenuationCaveat = `[
	*allow_dev($1, $2) <- arg(#ambient, $1, $2)
		@ 	$1 == "env",
			$2 == "DEV"
]`

func main() {
	for _, role := range []string{"guest", "developer", "admin"} {
		token, err := login(role)
		if err != nil {
			panic(err)
		}

		token, err = signToken(token)
		if err != nil {
			panic(err)
		}

		testAuthorization(role, token)
	}

	// try out attenuation
	devToken, err := login("developer")
	if err != nil {
		panic(err)
	}
	attToken, err := attenuate(devToken)
	if err != nil {
		panic(err)
	}

	attToken, err = signToken(attToken)
	if err != nil {
		panic(err)
	}

	testAuthorization("attenuated", attToken)
}

func testAuthorization(role string, token string) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial("localhost:8888", opts...)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	c := pb.NewDemoClient(conn)

	md := metadata.Pairs("authorization", token)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	_, err = c.Status(ctx, &pb.StatusRequest{})
	printStatus(role, "ANY", "Status", err)

	for envName, env := range pb.Env_value {
		_, err := c.Create(ctx, &pb.CreateRequest{
			Env:    pb.Env(env),
			Entity: &pb.Entity{Name: "entity1", Value: 42},
		})
		printStatus(role, envName, "Create", err)
	}

	for envName, env := range pb.Env_value {
		_, err := c.Read(ctx, &pb.ReadRequest{
			Env:        pb.Env(env),
			Names:      []string{"entity1"},
			ExpireTime: timestamppb.New(time.Now()),
			Stuff:      map[string]*pb.Entity{"foo42": {Name: "foo", Value: 42}, "bar31": {Name: "bar", Value: 31}},
			Stuff2:     map[int64]*pb.Entity{1: {Name: "foo", Value: 42}, 2: {Name: "bar", Value: 31}},
			Stuff3:     map[bool]*pb.Entity{true: {Name: "foo", Value: 42}, false: {Name: "bar", Value: 31}},
		})
		printStatus(role, envName, "Read", err)
	}

	for envName, env := range pb.Env_value {
		_, err := c.Update(ctx, &pb.UpdateRequest{
			Env:    pb.Env(env),
			Entity: &pb.Entity{Name: "entity1", Value: 42},
		})
		printStatus(role, envName, "Update", err)
	}

	for envName, env := range pb.Env_value {
		_, err := c.Delete(ctx, &pb.DeleteRequest{
			Env:  pb.Env(env),
			Name: "entity1",
		})
		printStatus(role, envName, "Delete", err)
	}
	fmt.Println()
}

func printStatus(role, envName, method string, err error) {
	var auth, msg string
	if errors.Is(err, authorization.ErrNotAuthorized) {
		auth = "DENIED"
		s, _ := status.FromError(err)
		msg = s.Message()
	} else if err != nil {
		auth = "FAILED"
		msg = err.Error()
	} else {
		auth = "ALLOWD"
		msg = "ok"
	}
	fmt.Printf("[%s][%s][%s] %s response: %s\n", role, envName, auth, method, msg)
}

// login simulate an authorization server returning a biscuit
func login(role string) (string, error) {
	rootPrivBytes, err := ioutil.ReadFile("./root.private.demo.key")
	if err != nil {
		return "", err
	}
	sk, err := sig.NewPrivateKey(rootPrivBytes)
	if err != nil {
		return "", err
	}
	root := sig.NewKeypair(sk)

	userPubKey, err := ioutil.ReadFile("./user.public.demo.key")
	if err != nil {
		return "", err
	}

	audience := "http://audience.local"
	audiencePrivKeyBytes, err := ioutil.ReadFile("./audience.private.demo.key")
	if err != nil {
		return "", err
	}
	audiencePrivKey, err := x509.ParseECPrivateKey(audiencePrivKeyBytes)
	if err != nil {
		return "", err
	}

	var rules []string
	switch role {
	case "admin":
		rules = append(guestPolicy, developerPolicy...)
		rules = append(rules, adminPolicy...)
	case "developer":
		rules = append(guestPolicy, developerPolicy...)
	case "guest":
		rules = guestPolicy
	default:
		return "", fmt.Errorf("unknown role: %s", role)
	}

	builder := biscuit.NewBuilder(rand.Reader, root)
	builder, err = signedbiscuit.WithSignableFacts(builder, audience, audiencePrivKey, userPubKey, time.Now().Add(5*time.Minute), &signedbiscuit.Metadata{
		ClientID:  "",
		IssueTime: time.Now(),
		UserEmail: "user@email.com",
		UserID:    "userID",
	})
	if err != nil {
		return "", err
	}

	p := parser.New()
	for _, r := range rules {
		if err := builder.AddAuthorityRule(p.Must().Rule(r)); err != nil {
			return "", nil
		}
	}
	for _, c := range caveats {
		if err := builder.AddAuthorityCaveat(p.Must().Rule(c)); err != nil {
			return "", nil
		}
	}

	bisc, err := builder.Build()
	if err != nil {
		return "", err
	}

	ser, err := bisc.Serialize()
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(ser), nil
}

// testAttenuation simulate a developer attenuating his token
// to only allows operations on DEV environment and forbid STAGING
func attenuate(token string) (string, error) {
	rng := rand.Reader
	rootKey := sig.GenerateKeypair(rng)

	newToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	newBiscuit, err := biscuit.Unmarshal(newToken)
	if err != nil {
		return "", err
	}

	builder := newBiscuit.CreateBlock()

	p := parser.New()

	newCaveat := p.Must().Caveat(attenuationCaveat)
	if err := builder.AddCaveat(newCaveat); err != nil {
		return "", err
	}

	attenuatedNewBiscuit, err := newBiscuit.Append(rng, rootKey, builder.Build())
	if err != nil {
		return "", err
	}

	ser, err := attenuatedNewBiscuit.Serialize()
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(ser), nil
}

func signToken(token string) (string, error) {
	decToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	rootPubBytes, err := ioutil.ReadFile("./root.public.demo.key")
	if err != nil {
		return "", err
	}
	rootPubKey, err := sig.NewPublicKey(rootPubBytes)
	if err != nil {
		return "", err
	}

	userPrivKeyBytes, err := ioutil.ReadFile("./user.private.demo.key")
	if err != nil {
		return "", err
	}
	userPrivKey, err := x509.ParseECPrivateKey(userPrivKeyBytes)
	if err != nil {
		return "", err
	}
	userKeypair, err := signedbiscuit.NewECDSAKeyPair(userPrivKey)
	if err != nil {
		return "", err
	}

	signedToken, err := signedbiscuit.Sign(decToken, rootPubKey, userKeypair)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(signedToken), nil
}
