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
    """<activity date="({time}\d\d\d\d-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})" name="(|({activity}[^"]{1,2000}))" host="(|({host}[^"]{1,2000}))" desc="(|({=activity}[^"]{1,2000}))""""
    """<user id="(|({user_email}[^@"]{1,2000}?@({email_domain}[^"]{1,2000}))|({user}[^"]{1,2000}))" guid="(|({guid}[^"]{1,2000}))" name="(|({user_fullname}[^"]{1,2000}))""""
  ]
}
```