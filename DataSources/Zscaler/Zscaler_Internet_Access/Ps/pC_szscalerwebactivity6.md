#### Parser Content
```Java
{
Name = s-zscaler-web-activity-6
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|LOGINNAME|""", """|CLIENTIP|""", """|URL|""", """|URLCAT|""", """|ACTION|""", """|ZSCALER|""" ]
  Fields = [
    """HOST\|({host}[^\|]{1,2000})""",
    """CONTENTTYPE\|([^\|]{0,2000}\|){2}(NA|({user}[^\|]{1,2000}?))\|(NA|({host}[\w\-.]{1,2000}))""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """LOGINNAME\|(({user_email}[^\|]{1,2000}@[^\|]{1,2000})|({user}[^\|\s]{1,2000}))\|""",
    """REASON\|({proxy_action}[^\|]{1,2000})""",
    """ACTION\|({action}[^\|]{1,2000})""",
    """REQMETHOD\|(NA|({method}[^\|]{1,2000}))""",
    """CLIENTIP\|({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """DESTINATIONIP\|({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """PROTOCOL\|({protocol}[^|]{1,2000})""",
    """URL\|({full_url}[^|]{1,2000})""",
    """URL\|((\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\/:\|"]{1,2000}))(:({dest_port}\d{1,100}))?(\/({uri_path}[^?\|\s]{1,2000}))?(\?({uri_query}[^\|,]{1,2000}))?\|""",
    """URLCAT\|({category}[^|]{1,2000})""",
    """USERAGENT\|(Unknown|({user_agent}[^|]{1,2000}))""",
    """REQSIZE\|({bytes_out}\d{1,100})""",
    """RESPCODE\|({result_code}\d{1,100})""",
    """RESPSIZE\|({bytes_in}\d{1,100})""",
    """APPNAME\|({app}[^|]{1,2000})""",
    """APPCLASS\|({app_class}[^|]{1,2000})""",
    """DLPDICT\|(None|({dlp_dict}[^|]{1,2000}))""",
    """DLPENGINE\|(None|({dlp_eng}[^|]{1,2000}))""",
    """LOCATION\|(None|({location}[^|]{1,2000}))""",
    """DEPARTMENT\|(None|({department}[^|]{1,2000}))""",
    """MALWARECAT\|(None|({malware_category}[^|]{1,2000}))""",
    """CONTENTTYPE\|(None|({mime}[^\|]{1,2000}))"""
    ]


}
```