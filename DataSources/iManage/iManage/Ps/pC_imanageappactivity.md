#### Parser Content
```Java
{
Name = imanage-app-activity
  Vendor = iManage
  Product = iManage
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Access Permitted""","""iManage""","""ACTIVITY:""" ]
  Fields = [
                        """ACTIVITY_DATE:\s{0,100}"{1,20}({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})""",
                        """exabeam_host=({host}[^\s]{1,2000})""",
                        """DOCNUMBER:\s{0,100}"{1,20}({resource}[^"]{1,2000})"{1,20}""",
                        """ACTIVITY:\s"{1,20}({activity}[^"]{1,2000})"{1,20}""",
                        """APPNAME:\s{0,100}"{1,20}({app}[^"]{1,2000})"{1,20}""",
                        """DOCNAME:\s{0,100}"{1,20}({object}[^"]{1,2000})"{1,20}""",
                        """AUTHOR_NAME:\s{0,100}"{1,20}({user_fullname}.+?)\s{0,100}"{1,20}""",
                        """OPERATOR_ID:\s{0,100}"{1,20}({user}[^"]{1,2000})"{1,20}""",
                         """OPERATOR_NAME:\s{0,100}"{1,20}({operator_name}.+?)\s{0,100}"{1,20}""",
                        """CLIENT_ID:\s{0,100}"{1,20}({client_id}[^"]{1,2000})"{1,20}""",
                         """CLIENT_NAME:\s{0,100}"{1,20}({client_name}[^"]{1,2000})"{1,20}""",
                        """SECURED:\s{0,100}"{1,20}({secured}[^"]{1,2000})"{1,20}"""
  ]
}
}
```