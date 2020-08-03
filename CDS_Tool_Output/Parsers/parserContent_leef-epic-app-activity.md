#### Parser Content
```Java
{
Name = leef-epic-app-activity
  Vendor = Epic
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Epic|Security-SIEM|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w.\-]+) LEEF:([^\|]*\|)({app}[^\|]+)\|([^\|]*\|){2}({activity}[^\|]+)""",
    """shost=({src_host}.+?)(\s+\w+=|\s*$)""",
    """usrName=({user_id}.+?)(\s+\w+=|\s*$)""",
    """usrName=\w+-({user_fullname}[^=]+?)-""",
    """resource=({resource}.+?)(\s+\w+=|\s*$)""",
    """devTime=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """E3MID=({record_id}.+?)(\s+\w+=|\s*$)""",
    """LOGIN_LDAP_ID=({user}.+?)(\s+\w+=|\s*$)""",
    """IP=(?:({dest_ip}[a-fA-F\d.:]+)\/)?({src_ip}[a-fA-F\d.:]+)""",
    """LOGINERROR=({failure_reason}[^\s].*?)(\s+\w+=|\s*$)""",
    """ERRMSG=({failure_reason}[^\s].*?)(\s+\w+=|\s*$)""",
    """UID=({user_id}.+?)(\s+\w+=|\s*$)""",
    """NEWDEPARTMENT=({object}.+?)(\s+\w+=|\s*$)""",
    """BTGNOACCESSREAS=({additional_info}.+?)(\s+\w+=|\s*$)""",
  ]
}
```