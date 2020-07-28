#### Parser Content
```Java
{
Name = cef-db2-security-alert-2
  Vendor = IBM
  Product = IBM DB2
  Lms = ArcSight
  DataType = "alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Enterprise-IT-Security""", """Security_System_Attack""" ]
  Fields = [
    """\s({time}\d+-\d+-\d+T\d+:\d+:\d+)\S*\s+({host}[\w\-.]+)\s+\w+\s""",
    """deviceProcessName=({host}[\w\-.]+)""",
    """act=({alert_name}.+?)\s+(\w+=|$)""",
    """cat=({category}.+?)\s+(\w+=|$)""",
    """cs2=({outcome}.+?)\s+(\w+=|$)""",
    """shost=({dest_host}[\w\-.]+)\s+(\w+=|$)""",
    """deviceProcessName=({process_name}.+?)\s+(\w+=|$)""",
    """cs1=({additional_info}.+?)\s+(\w+=|$)""",
    """duser=({user}.+?)\s*\w+=""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}

{
  Name = ibm-auth-successful
  Vendor = IBM
  Product = IBM
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ind--bindDN""", """--Success""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+).*?ind--bindDN""",
    """uid=({user}[^\s,=]+)""",
    """client:\s*((:0|::1|({src_ip}[A-Fa-f:\d.]+?))(:({src_port}\d+))?)\-*connectionID:""",
  ]
}
```