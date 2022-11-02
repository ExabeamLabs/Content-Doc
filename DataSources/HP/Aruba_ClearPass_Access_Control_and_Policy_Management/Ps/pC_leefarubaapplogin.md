#### Parser Content
```Java
{
Name = leef-aruba-app-login
  DataType = "app-login"
  Conditions = [ """LEEF:""", """|Aruba Networks|ClearPass|""", """sub-cat=Logged in""", """cat=System Events""" ]
  Fields = ${ArubaClearParserTemplates.leef-aruba-format.Fields} [
     """sub-cat=({event_name}[^=]{1,2000}?)\s{1,100}\w+?=""",
     """Client IP Address:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
     """User:\s{0,100}({user}[^\s\\]{1,2000})""",
     """({app}ClearPass)"""
  ]
  DupFields = [ "event_name->activity" ]

leef-aruba-format = {
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = ArcSight
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s{1,100}LEEF:""",
    """devTime=({time}[^=]{1,2000}?)\s{1,100}\w+?=""",
    """action=(None|({activity}[^=]{1,2000}?))\s{1,100}\w+?=""",
    """src=({dest_ip}[a-fA-F\d.:]{1,2000}?)\s{1,100}\w+?="""
   
}
```