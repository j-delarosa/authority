
class AuthorityError(Exception):


    def __init__(self, msg, status = 0, deets = None):

        self.msg = msg
        self.detail = deets
        self.status = status

    def _status(self):

        return {"status": self.status}

    def _message(self):

        return {"message": self.msg} 

    def _details(self):
        if self.detail:
            return {"details": str(self.detail)}
        return {}

    def __str__(self):
        result = {}

        for something in [self._status, self._message, self._details]:
            result.update(something())

        return str(result)


class IncorrectRegistration(AuthorityError):
    '''
    Registration did not have all the necessary items
    '''


class TokenMalformed(AuthorityError):
    '''
    someone tried to modify the token contents ot it is incomplete
    '''


class NameTaken(AuthorityError):
    '''
    the name has already been taken, they need to reach out to update'''

class NameNotFound(AuthorityError):

    '''This happens whenever a name was attempted to be retireved but does not exist'''