#### Parser Content
```Java
{
Name = cef-okta-app-activity
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Okta""", """cs6=""", """"targets":""", """"eventId":""" ]
  Fields=[
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"published":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\Wfname=({object}(?![\w\-]{25}).+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]+?)\s+(\w+=|$)""",
    """"action":[^}]+?"message":"({additional_info}[^"]+)""",
    """"action":[^}]+?"objectType":"({activity}[^"]+)""",
    """"(targets|actors)":[^\]]+?"objectType":"User"[^\]\}]+?"displayName":"((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]+))""",
    """"(targets|actors)":[^\]]+?"displayName":"((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]+))[^\]\}]+?"objectType":"User"""",
    """(s|d)?user\\*=({user_email}[^\s@,]+@({email_domain}[^\s@,]+))""",
    """(s|d)?user\\*=(anonymous|({user}[^\s@,]+))(\s|\||,)""",
    """"(targets|actors)":[^\]]+?"objectType":"User"[^\]\}]+?"login":"({user_email}[^"]+)""",
    """"(targets|actors)":[^\]]+?"login":"({user_email}[^@]+@({email_domain}[^"]+))[^\]\}]+?"objectType":"User"""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"displayName":"(UNKNOWN|({browser}[^"]+))""",
    """"actors":[^\]]+?"displayName":"(UNKNOWN|({browser}[^"]+))[^\]\}]+?"objectType":"Client"""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"ipAddress":"(|({src_ip}[^"]+))""",
    """"actors":[^\]]+?"ipAddress":"(|({src_ip}[^"]+))[^\]\}]+?"objectType":"Client"""",
    """"target(s)?":[^\]]+?"objectType":"User"[^\]\}]+?"displayName":"({target_user}[^"]+)""",
    """"target(s)?":[^\]]+?"displayName":"({target_user}[^"]+)[^\]\}]+?"objectType":"User"""",
    """"target(s)?":[^\]\}]+?"objectType":"({object_type}[^"]+)""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"id":"({user_agent}[^"]+)""",
    """"actors":[^\]]+?"id":"({user_agent}[^"]+)[^\]\}]+?"objectType":"Client"""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"id":"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"""",
    """"actors":[^\]]+?"id":"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"[^\]\}]+?"objectType":"Client"""",
    """({app}Okta)""",
    """"id":"({object}[^"]+)"[^\}\]]*"objectType":"AppInstance"""",
    """"objectType":"AppInstance"[^\}\]]*"id":"({object}[^"]+)"""",
    """requestClientApplication=({app}[^=]+?)\s*\w+=""",
    """\Wsuid=(anonymous|({user_email}[^@=]+@[^@=]+?)|({user}[^\s=]+?))(\s+\w+=|\s*$)""",
    """requestUri":\s*"({request_uri}[^"]+?)\s*"""",
  ]
}
```