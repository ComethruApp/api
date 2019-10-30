from flask_seeder import Seeder, Faker, generator
from models import School, User

class SchoolSeeder(Seeder):
    def run(self):
        yale = School(
            name='Yale University',
            nickname='Yale',
            color='00356b',
            domain='yale.edu')
        self.db.session.add(yale)
        self.db.session.commit()


class DemoSeeder(Seeder):
    def run(self):
        # Create a new Faker and tell it how to create User objects
        faker = Faker(
            cls=User,
            init={
                "id": generator.Sequence(),
                "name": generator.Name(),
                "age": generator.Integer(start=20, end=100)
            }
        )

        # Create 5 users
        for user in faker.create(5):
            print("Adding user: %s" % user)
        self.db.session.add(user)
        self.db.session.commit()
