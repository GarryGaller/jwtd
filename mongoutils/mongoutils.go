package mongoutils

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	//"go.mongodb.org/mongo-driver/mongo/readpref"
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

func (m *Mongo) Connect(ctx context.Context, uri string) error {
	/*  */
	var err error

	mongoOptions := m.Options.ApplyURI(uri)
	client, err := mongo.Connect(ctx, mongoOptions)

	if err == nil {
		m.Client = client
	}

	return err
}
