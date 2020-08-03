#### Parser Content
```Java
{
Name = s-cyberark-tpm-account-switch
    Vendor = CyberArk
    Product = Privileged Session Manager
    Lms = Splunk
    DataType = "account-switch"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """Operation: Retrieve Password ObjectType:""" ]
    Fields = [
        	"""Operation: ({activity}.*?) ObjectType""",
		"""({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
		"""(AdminName|UserName):\s({user}.+)\sOperation""",
    """Target:\s*(?:({account_domain}[^\\\/]+)[\\\/]+)?({account}.+?)\s*Role:""",
		""":\d\d\s({host}[^=]+)\sPAR""",
		"""PAR\[({event_code}\d+)"""
    ]
    DupFields = [ "host->dest_host" ]
}
```