#### Parser Content
```Java
{
Name = cef-juniper-account-deleted
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "account-deleted"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|User deleted|""" ]
  Fields = [
	"""\Wrt=({time}\d{1,100})""",
	"""\Wdvchost=({host}[\w\-.]{1,2000})""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
	"""\Wsuser=(System|({user}[^\s]{1,2000}))""",
	"""\Wduser=({target_user}[^\s]{1,2000})""",
	"""\Wshost=({src_host}[\w\-.]{1,2000})""",
        """\Wahost=({dest_host}.*?)\s\w+=""",
  ]
  DupFields = [ "target_user->account_name" ]
}
```