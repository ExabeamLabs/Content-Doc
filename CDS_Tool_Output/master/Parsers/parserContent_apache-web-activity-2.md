#### Parser Content
```Java
{
Name = apache-web-activity-2
  Vendor = NGINX
  Product = NGINX
  Conditions = [ """ nginx: """, """ HTTP/1.""", """] """" ]
  Fields = ${ApacheParserTemplates.apache-web-activity.Fields}[
    """({host}[\w\-.]+)\s+nginx:""",
  ]
}
```