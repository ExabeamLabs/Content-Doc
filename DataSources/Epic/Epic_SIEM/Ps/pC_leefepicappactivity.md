#### Parser Content
```Java
{
Name = leef-epic-app-activity
  Vendor = Epic
  Product = Epic SIEM
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Epic|Security-SIEM|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w.\-]{1,2000}) LEEF:([^\|]{0,2000}\|)({app}[^\|]{1,2000})\|([^\|]{0,2000}\|){2}({activity}[^\|]{1,2000})""",
    """({host}[\w.\-]{1,2000}),"{1,20}LEEF:[^\|]{1,2000}\|({app}[^\|]{1,2000})\|([^\|]{1,2000}\|){2}({activity}[^\|]{1,2000})""",
    """shost=({src_host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """usrName=({user_id}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """usrName=\w+-({user_fullname}[^=]{1,2000}?)\s{0,100}-"""
    """resource=\s{0,100}({resource}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """devTime=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """E3MID=({record_id}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """LOGIN_LDAP_ID=({user}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """IP=(?:({dest_ip}[a-fA-F\d.:]{1,2000})\/)?({src_ip}[a-fA-F\d.:]{1,2000})""",
    """LOGINERROR=({failure_reason}[^\s]{0,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """ERRMSG=({failure_reason}[^\s]{0,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """UID=({user_id}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """NEWDEPARTMENT=({object}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """BTGNOACCESSREAS=({additional_info}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```