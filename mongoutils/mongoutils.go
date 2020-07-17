package mongoutils

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type Mongo struct {
	Options        *options.ClientOptions
	Client         *mongo.Client
	Collection     *mongo.Collection
	DB             string
	CollectionName string
	Ctx            context.Context
}

func (m *Mongo) GetOrCreate(database, table string) *mongo.Collection {
	/*  */
	collection := m.Client.Database(database).Collection(table)
	return collection
}

func (m *Mongo) InsertOne(
	ctx context.Context,
	doc interface{}) (*mongo.InsertOneResult, error) {
	/*  */

	var err error

	if m.Collection == nil {
		m.Collection = m.GetOrCreate(m.DB, m.CollectionName)
	}

	result, err := m.Collection.InsertOne(ctx, doc)

	return result, err
}

func (m *Mongo) FindOne(
	ctx context.Context,
	filter interface{}) *mongo.SingleResult {
	/*  */

	if m.Collection == nil {
		m.Collection = m.GetOrCreate(m.DB, m.CollectionName)
	}

	result := m.Collection.FindOne(ctx, filter)

	return result
}

func (m *Mongo) UpsertOne(
	ctx context.Context,
	filter interface{},
	update interface{}) (*mongo.UpdateResult, error) {
	/*  */
	var err error
	opts := options.Update().SetUpsert(true)

	if m.Collection == nil {
		m.Collection = m.GetOrCreate(m.DB, m.CollectionName)
	}

	result, err := m.Collection.UpdateOne(ctx, filter, update, opts)

	return result, err
}

func (m *Mongo) UpdateOne(
	ctx context.Context,
	filter interface{},
	update interface{}) (*mongo.UpdateResult, error) {
	/*  */
	var err error

	if m.Collection == nil {
		m.Collection = m.GetOrCreate(m.DB, m.CollectionName)
	}

	result, err := m.Collection.UpdateOne(ctx, filter, update)

	return result, err
}

func (m *Mongo) DeleteOne(
	ctx context.Context,
	filter interface{}) (*mongo.DeleteResult, error) {
	/*  */
	var err error

	if m.Collection == nil {
		m.Collection = m.GetOrCreate(m.DB, m.CollectionName)
	}
	result, err := m.Collection.DeleteOne(ctx, filter)

	return result, err
}

func (m *Mongo) DeleteMany(
	ctx context.Context,
	filter interface{}) (*mongo.DeleteResult, error) {
	/*  */
	var err error

	if m.Collection == nil {
		m.Collection = m.GetOrCreate(m.DB, m.CollectionName)
	}

	result, err := m.Collection.DeleteMany(ctx, filter)

	return result, err

}

func (m *Mongo) Connect(
	ctx context.Context,
	uri string,
	credentials *options.Credential) error {
	/*  */
	var err error

	mongoOptions := m.Options.ApplyURI(uri)
	if credentials != nil {
		mongoOptions.SetAuth(*credentials)
	}
	client, err := mongo.Connect(ctx, mongoOptions)

	if err == nil {
		if err = client.Ping(ctx, nil); err != nil {
            return err
        }
        
        m.Client = client
	}

	return err
}

func (m *Mongo) RunCommand(
	ctx context.Context,
	command interface{},
	opts ...*options.RunCmdOptions,
) *mongo.SingleResult {

	singleResult := m.Client.Database(ctx.Value("db").(string)).
        RunCommand(ctx, command, opts...)
    return singleResult
}

func (m Mongo) CreateReplicaSet(
    ctx context.Context, 
    replicaName string) *mongo.SingleResult {

	opt := options.RunCmd().SetReadPreference(readpref.Primary())
	m.Options.SetReplicaSet(replicaName)
	config := bson.M{
		"_id": replicaName,
		"members": []bson.M{
			bson.M{"_id": 0, "host": "localhost:27017"},
			bson.M{"_id": 1, "host": "localhost:27018"},
			bson.M{"_id": 2, "host": "localhost:27019", "arbiterOnly": true},
		},
	}
	command := bson.M{"replSetInitiate": config}
	singleResult := m.Client.Database(ctx.Value("db").(string)).
        RunCommand(ctx, command, opt)
    return singleResult
}

func (m Mongo) CreateUser(
    ctx context.Context, 
    userDB, passwordDB string) *mongo.SingleResult {
    
    opt := options.RunCmd().SetReadPreference(readpref.Primary())
	roles := []bson.M{
		bson.M{"role": "readWrite", "db": ctx.Value("db").(string)},
	}
	command:= bson.M{
		"createUser": userDB,
		"pwd":        passwordDB,
		"roles":      roles,
	}

	opt = options.RunCmd().SetReadPreference(readpref.Primary())
	singleResult := m.Client.Database(ctx.Value("db").(string)).
        RunCommand(ctx, command, opt)
    return singleResult
}
