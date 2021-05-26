#### Parser Content
```Java
{
Name = s-cyberark-tpm-login
    Vendor = CyberArk
    Product = Privileged Session Manager
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """Operation: Login ObjectType:""" ]
    Fields = [
		""":\d\d\s({host}[^=]{1,2000})\sPAR""",
                """({src_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})""",
		"""({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
                """(AdminName|UserName): ({user}[^\s]{0,2000})\s""",
                """TargetURL=({app}.+?).\s""",
                """OtherInfo: ({protocol}.*?)\s{1,100}TargetURL""",
		"""PAR\[({event_code}\d{1,100})""",
		"""ObjectType:\s({event_subtype}.+)\sTarget:"""
    ]
}
```