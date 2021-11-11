#### Parser Content
```Java
{
Name = edocs-app-activity
  Vendor = eDocs
  Product = eDocs
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Access Permitted""","""eDocs""","""Activity:""" ]
  Fields = [
                        """ACTIVITY_DATE:\s{0,100}"{1,20}({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})""",
                        """"{1,20}eDocs\s{0,100}-\s{0,100}({host}[^"]{1,2000})"{1,20}""",
                        """DOCNUMBER:\s{0,100}"{1,20}({resource}\d{1,100})"{1,20}""",
                        """Activity:\s{0,100}"{1,20}({activity}[^"]{1,2000})"{1,20}""",
                        """APPLICATION:\s{0,100}"{1,20}({app}[^"]{1,2000})"{1,20}""",
                        """DOCNAME:\s{0,100}"{1,20}({object}[^"]{1,2000})"{1,20}""",
                        """AUTHOR_ID:\s{0,100}"{1,20}({user_id}[^"]{1,2000})"{1,20}""",
                        """AUTHOR_NAME:\s{0,100}"{1,20}({user_fullname}[^"]{1,2000})"{1,20}""",
                        """CLIENT_ID:\s{0,100}"{1,20}({client_id}[^"]{1,2000})"{1,20}""",
                        """CLIENT_NAME:\s{0,100}"{1,20}({client_name}[^"]{1,2000})"{1,20}""",
                        """TYPIST_ID:\s{0,100}"{1,20}({user}[^"]{1,2000})"{1,20}""",
  ]
}
}
```