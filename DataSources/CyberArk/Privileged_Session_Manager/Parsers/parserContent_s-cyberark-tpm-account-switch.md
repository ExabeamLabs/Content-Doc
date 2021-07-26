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
    """Target:\s{0,100}(?:({account_domain}[^\\\/]{1,2000})[\\\/]{1,2000})?({account}.+?)\s{0,100}Role:""",
		""":\d\d\s({host}[^=]{1,2000})\sPAR""",
		"""PAR\[({event_code}\d{1,100})"""
    ]
    DupFields = [ "host->dest_host" ]
}
```