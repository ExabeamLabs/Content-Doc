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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """({host}[\w.\-]+) LEEF:([^\|]*\|)({app}[^\|]+)\|([^\|]*\|){2}({activity}[^\|]+)""",
    """({host}[\w.\-]+),"{1,20}LEEF:[^\|]+\|({app}[^\|]+)\|([^\|]+\|){2}({activity}[^\|]+)""",
    """shost=({src_host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """usrName=({user_id}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """usrName=\w+-({user_fullname}[^=]+?)\s{0,100}-"""
    """resource=\s{0,100}({resource}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """devTime=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """E3MID=({record_id}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """LOGIN_LDAP_ID=({user}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """IP=(?:({dest_ip}[a-fA-F\d.:]+)\/)?({src_ip}[a-fA-F\d.:]+)""",
    """LOGINERROR=({failure_reason}[^\s]*?)(\s{1,100}\w+=|\s{0,100}$)""",
    """ERRMSG=({failure_reason}[^\s]*?)(\s{1,100}\w+=|\s{0,100}$)""",
    """UID=({user_id}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """NEWDEPARTMENT=({object}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """BTGNOACCESSREAS=({additional_info}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```