#### Parser Content
```Java
{
Name = forcepoint-web-activity-2
  Vendor = Forcepoint
  Product = Websense Secure Gateway
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """logtype="ForcepointAPIExportCSVtoKV"""", """Referrer_URL_-_Full="""", """HTTP_Status_Code=""",  ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """Action="(?:-|({action}[^"]{1,2000}))""",
    """Bytes_Sent="({bytes_in}\d{1,100})"""",
    """Bytes_Received="({bytes_out}\d{1,100})"""",
    """Category_Name ="(Unknown|({category}[^"]{1,2000}))"""",
    """Destination_IP="(0\.0\.0\.0|({dest_ip}[\da-fA-F:\.]{1,2000}))"""",
    """Source_IP="({src_ip}[\da-fA-F:\.]{1,2000})"""",
    """\sURL_-_Full="({full_url}({protocol}[^:]{1,2000}):\/\/({web_domain}[^\/:\s]{1,2000}))?({uri_path}\/?[^\?"]{1,2000})?(\?({uri_query}[^"]{1,2000}))?"""",
    """Referrer_URL_-_Full="((?i)None|({referrer}[^"]{1,2000}))""",
    """Workstation="(Not available|({host}[^"]{1,2000}))"""",
    """Request_Method="({method}[^"]{1,2000})"""",
    """Full_MIME_Type="(None|({mime}[^"]{1,2000}))"""",
    """User_Agent="(None|({user_agent}[^"]{1,2000}))"""",
    """HTTP_Status_Code="({result_code}\d{1,100})"""",
    """Workstation="(Not available|({src_host}[^"]{1,2000}))"""",
    """User="(Not available|({user_email}[^@\s"]{1,2000}@[^@\s"]{1,2000})|({user}[^"\s]{1,2000}))""""
    """File_Name ="((?i)none|({file_name}[^"]{1,2000}))"""",
    """File_Type="((?i)Unknown|({file_type}[^"]{1,2000}))"""
  ]
}
}
```