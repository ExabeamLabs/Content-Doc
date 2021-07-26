#### Parser Content
```Java
{
Name = cef-securesphere-db-alert-1
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = ArcSight
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|SecureSphere|""", """cat=Alert""", """cs12Label=HostName""", """cs3Label=ServiceName""" ]
  Fields = [
    """\Wrt=({time}\w+ \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\s({host}[\w\.-]{1,2000})\s{1,100}CEF:""",
    """\Wduser=(|({user}.+?))\s{0,100}(\w+=|\||$)""",
    """\Wcs1=(|({alert_name}[^=]{1,2000}?))\s{0,100}(\w+=|\||$)""",
    """\Wcs13=({database_name}[^=\s]{1,2000}?)\s{0,100}(\w+=|\||$)""",
    """\Wcs4=(|({app}[^=]{1,2000}?))\s{0,100}(\w+=|\||$)""",
    """\Wcs3=(|({service_name}[^=]{1,2000}?))\s{0,100}(\w+=|\||$)""",
    """\Wcs2=(|({server_group}[^=]{1,2000}?))\s{0,100}(\w+=|\||$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wcs12=(|({dest_host}.+?))\s{0,100}(\w+=|\||$)""",
    """\Wsev=(|({alert_severity}.+?))\s{0,100}(\w+=|\||$)""",
    """\Wcs16=(|({additional_info}.+?))\s{0,100}(\w+=|\||$)""",
    """\Wcs16=N/A\s{0,100}\(({additional_info}.+?)\)""",
    """\Wcs14=(|({database_schema}.+?))\s{0,100}(\w+=|\||$)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```