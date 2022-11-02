#### Parser Content
```Java
{
Name = cef-iis-web-activity-1
  Vendor = Microsoft
  Product = IIS
  Lms = ArcSight
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd 'time' HH:mm:ss"
  Conditions = [ """ s-sitename """, """ s-computername """,""" cs-bytes """,""" cs(Referer) """,""" cs(User-Agent) """ ]
  Fields = [
    """date\s({time}\d\d\d\d-\d\d-\d\d\stime\s\d\d:\d\d:\d\d)""",
    """\scs-host\s(-|({web_domain}[^\s]{1,2000}))\s""",
    """\sc-ip\s({src_ip}[a-fA-F\d.:]{1,2000})\s""",
    """\ss-ip\s({dest_ip}[a-fA-F\d.:]{1,2000})\s""",
    """\scs-username\s(-|(({domain}[^\\\s]{1,2000})\\+)?({user}[^\s\\]{1,2000}))\s""",
    """\ss-port\s(-|({dest_port}\d{1,5}))\s""",
    """\scs-method\s({method}[^\s]{1,2000})\s""",
    """\ssc-status\s(-|({result_code}\d{1,5}))\s""",
    """\ssc-bytes\s({bytes_out}\d{1,20})\s""",
    """\scs-bytes\s({bytes_in}\d{1,20})\s""",
    """\scs\(User-Agent\)\s({user_agent}[^\s]{1,2000})\s"""
    """\scs\(Referer\)\s(-|({referrer}[^\s]{1,2000}))\s""",
    """\scs-uri-query\s(-|({uri_query}[^\s]{1,2000}?))\s""",
    """\scs-uri-stem\s(-|\/|({uri_path}[^\s]{1,2000}?))\s""",
    """\ss-computername\s({dest_host}[^\s]{1,2000})\s""",
  ]


}
```