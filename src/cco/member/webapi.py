#
# cco.member.webapi
#

from cco.webapi.server import TypeHandler


class Users(TypeHandler):

    def create(self):
        data = self.getInputData()
        print '***', data
        #create_or_update_object(self.loopsRoot, 'person', data)
        return self.success()
