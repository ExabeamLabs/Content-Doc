#### Parser Content
```Java
{
Name = netdocs-app-activity
  Vendor = NetDocs
  Product = NetDocs
  DataType = "app-activity"
  Lms = Direct
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """</activity>""", """<activity date="""", """<user id="""", """guid="""", """host="""", """name="""", """custom-condition-CONT-7666"""]
  Fields = [
    """<activity date="({time}\d\d\d\d-\d+-\d+T\d+:\d+:\d+)" name="(|({activity}[^"]+))" host="(|({host}[^"]+))" desc="(|({=activity}[^"]+))""""
    """<user id="(|({user_email}[^@"]+?@({email_domain}[^"]+))|({user}[^"]+))" guid="(|({guid}[^"]+))" name="(|({user_fullname}[^"]+))""""
  ]
}
```