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
    """\Wrt=({time}\w+ \d+ \d+ \d+:\d+:\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """\s({host}[\w\.-]+)\s+CEF:""",
    """\Wduser=(|({user}.+?))\s*(\w+=|\||$)""",
    """\Wcs1=(|({alert_name}[^=]+?))\s*(\w+=|\||$)""",
    """\Wcs13=({database_name}[^=\s]+?)\s*(\w+=|\||$)""",
    """\Wcs4=(|({app}[^=]+?))\s*(\w+=|\||$)""",
    """\Wcs3=(|({service_name}[^=]+?))\s*(\w+=|\||$)""",
    """\Wcs2=(|({server_group}[^=]+?))\s*(\w+=|\||$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wcs12=(|({dest_host}.+?))\s*(\w+=|\||$)""",
    """\Wsev=(|({alert_severity}.+?))\s*(\w+=|\||$)""",
    """\Wcs16=(|({additional_info}.+?))\s*(\w+=|\||$)""",
    """\Wcs16=N/A\s*\(({additional_info}.+?)\)""",
    """\Wcs14=(|({database_schema}.+?))\s*(\w+=|\||$)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```