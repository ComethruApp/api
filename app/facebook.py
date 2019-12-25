from app import app
import facebook

class Facebook:
    graph = facebook.GraphAPI(access_token=app.config['FACEBOOK_API_TOKEN'], version='3.1')

    def get_friends(self, facebook_user_id):
        return self.graph.get_all_connections(id=str(facebook_user_id), connection_name='friends', fields='id')

facebook = Facebook()
