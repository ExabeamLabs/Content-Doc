#### Parser Content
```Java
{
Name = cef-trendmicro-dlp-alert-1
  Conditions = [ """|Trend Micro|""", """|Data Loss Prevention|""" ]
}

{
  Name = cef-trendmicro-dlp
  Vendor = Trend Micro
  Product = Deep Discovery Email Inspector
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Trend Micro|""", """|Deep Discovery Email Inspector|""" , """|MESSAGE_TRACKING|"""]
  Fields = [
        """\srt=({time}\W{3}\s\d+\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
        """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """\sdvchost=({host}[^\s]+)""",
        """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """duser=({user_email}[^\s]+)""",
        """\scs3=({outcome}[^\s]+)""",
        """msg=({subject}.+?)\scs2""",
        """cs5=({recipients}({recipient}[^;].+?@+({external_domain_recipient}[^;]+))[^\s]+)\s""",
        """cs4=({sender}.+?@+({external_domain_sender}[^\s]+))\scs5Label"""
        """\|({alert_severity}\d+)\|rt""",
        """cs1=({return_path}[^\s]+)\s"""
  ]
  DupFields = [ "sender->external_address" , "external_domain_sender->external_domain" , "user_email->email_user"]
}
 
{
  Name = trendmicro-cef-web-activity
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """|Trend Micro|Control Manager|""", """|WB:36|""" ]
  Fields = [
    """\Wrt=({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\s+\w+[\+\-]\d+:\d+)""",
    """({host}[\w\-.]+)\s+CEF:""",
    """\Wdvchost=({host}[^\s]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wcs1=({policy}.+?)\s+\w+=""",
    """\Wrequest=(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:\d+)?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s,]*)?))\s+(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\WdeviceFacility=({activity}.+?)\s+(\w+=|$)""",
    """\Wrequest=[^\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|re))+)\S+\s+(\w+=|$)""",
  ]
}
```