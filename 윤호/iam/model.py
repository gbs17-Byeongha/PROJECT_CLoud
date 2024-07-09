class ResultModel:
    def __init__(self, Object_name, arn, region, tag, policy_name, status, status_extended):
        self.Object_name = Object_name
        self.arn = arn
        self.tag = tag
        self.region = region
        self.policy_name = policy_name  
        self.status = status
        self.status_extended = status_extended