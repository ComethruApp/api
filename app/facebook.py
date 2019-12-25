from app import app
import facebook

class Facebook:
    graph = facebook.GraphAPI(access_token=app.config['FACEBOOK_API_TOKEN'], version='3.1')

    def get_friends(self, facebook_user_id):
        return self.graph.get_all_connections(id=facebook_user_id, connection_name='friends', fields='id')

    def get_events(self, facebook_user_id):
        return self.graph.get_all_connections(id=facebook_user_id, connection_name='events', fields='id,name')

facebook = Facebook()
