#### Parser Content
```Java
{
Name = s-cyberark-tpm-activity
    Vendor = CyberArk
    Product = Privileged Session Manager
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """Operation:""", """ObjectType:""", """OtherInfo:""" ]
    Fields = [
		"""Operation: ({activity}.*?) ObjectType""",
                """:\d\d\s({host}[^=]{1,2000})\sPAR""",
		"""({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
                """(AdminName|UserName): ({user}[^\s].+)\sOperation""",
                """Failed\?\s({event_subtype}\d)\s""",
		"""Target: ({app}[^\s].+)\sRole""",
		"""OtherInfo:\s({additional_info}.+)\s""",
		"""Role:\s({app_group}.+?)\s"""
    ]
}
```