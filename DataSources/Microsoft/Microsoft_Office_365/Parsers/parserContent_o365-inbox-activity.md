#### Parser Content
```Java
{
Name = o365-inbox-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""destinationServiceName=Office 365""" , """SkyFormation Cloud Apps Security""" , """permissions-updated""", """"ResultStatus"""" , """Add-MailboxPermission"""]
  Fields = [
     """"CreationTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
     """flexString1=({activity}[^\s]*)\srequest""",
     """\sby\s\[({user_email}[^@]+@({email_domain}[^\]]*))\]""",
     """ObjectId":"({resource}[^"]*)"""",
     """ResultStatus":"({outcome}[^"]*)"""",
     """Name":"AccessRights","Value":"({additional_info}[^"]*)"""",
     """destinationServiceName=(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
     """ClientIP":"\[?({src_ip}[^"\]]*)?\]?(:\d{5})""",
     """duser=([^=]+\/)?({object}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
   ]
}
```