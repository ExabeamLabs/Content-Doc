#### Parser Content
```Java
{
Name = cef-trendmicro-dlp
  Vendor = Trend Micro
  Product = Deep Discovery Email Inspector
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Trend Micro|""", """|Deep Discovery Email Inspector|""" , """|MESSAGE_TRACKING|"""]
  Fields = [
        """\srt=({time}\W{3}\s\d{1,100}\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
        """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """\sdvchost=({host}[^\s]{1,2000})""",
        """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """duser=({user_email}[^\s]{1,2000})""",
        """\scs3=({outcome}[^\s]{1,2000})""",
        """msg=({subject}.+?)\scs2""",
        """cs5=({recipients}({recipient}[^;].+?@+({external_domain_recipient}[^;]{1,2000}))[^\s]{1,2000})\s""",
        """cs4=({sender}.+?@+({external_domain_sender}[^\s]{1,2000}))\scs5Label"""
        """\|({alert_severity}\d{1,100})\|rt""",
        """cs1=({return_path}[^\s]{1,2000})\s"""
  ]
  DupFields = [ "sender->external_address" , "external_domain_sender->external_domain" , "user_email->email_user"]
}
```