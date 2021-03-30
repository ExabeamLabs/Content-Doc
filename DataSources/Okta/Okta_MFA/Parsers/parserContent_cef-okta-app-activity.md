#### Parser Content
```Java
{
Name = cef-okta-app-activity
  Vendor = Okta
  Product = Okta MFA
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Okta""", """cs6=""", """"targets":""", """"eventId":""" ]
  Fields=[
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """"published":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\Wfname=({object}(?![\w\-]{25}).+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """"action":.+?"message":"({additional_info}[^"]+)""",
    """"action":.+?"objectType":"({activity}[^"]+)""",
    """"(targets|actors)":[^\]]+?"objectType":"User"[^\]\}]+?"displayName":"({user_fullname}[^"]+)""",
    """"(targets|actors)":[^\]]+?"displayName":"({user_fullname}[^"]+)[^\]\}]+?"objectType":"User"""",
    """(s|d)?user\\*=({user_email}[^\s@,]+@[^\s@,]+)""",
    """(s|d)?user\\*=(anonymous|({user}[^\s@,]+))(\s|\||,)""",

    """"(targets|actors)":[^\]]+?"objectType":"User"[^\]\}]+?"login":"({user_email}[^"]+)""",
    """"(targets|actors)":[^\]]+?"login":"({user_email}[^"]+)[^\]\}]+?"objectType":"User"""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"displayName":"(UNKNOWN|({browser}[^"]+))""",
    """"actors":[^\]]+?"displayName":"(UNKNOWN|({browser}[^"]+))[^\]\}]+?"objectType":"Client"""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"ipAddress":"(|({src_ip}[^"]+))""",
    """"actors":[^\]]+?"ipAddress":"(|({src_ip}[^"]+))[^\]\}]+?"objectType":"Client"""",
    """"targets":[^\]]+?"objectType":"User"[^\]\}]+?"displayName":"({target_user}[^"]+)""",
    """"targets":[^\]]+?"displayName":"({target_user}[^"]+)[^\]\}]+?"objectType":"User"""",
    """"targets":.+?"objectType":"({object_type}[^"]+)""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"id":"({user_agent}[^"]+)""",
    """"actors":[^\]]+?"id":"({user_agent}[^"]+)[^\]\}]+?"objectType":"Client"""",
    """"actors":[^\]]+?"objectType":"Client"[^\]\}]+?"id":"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"""",
    """"actors":[^\]]+?"id":"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"[^\]\}]+?"objectType":"Client"""",
    """({app}Okta)""",
    """"id":"({object}[^"]+)"[^\}\]]*"objectType":"AppInstance"""",
    """"objectType":"AppInstance"[^\}\]]*"id":"({object}[^"]+)"""",
  ]
  DupFields = [ "additional_info->failure_reason" ]
}
```