#### Parser Content
```Java
{
Name = cef-websense-proxy
  Conditions = [ """|Websense|Web Security|""","""CEF:""", """in=""", """out=""", """cs3Label=ContentType"""]
  Fields = ${WPParserTemplates.wp-web-activity.Fields} [
      """\scat=({category_id}\d+)""",
      """\sreason=({reason}.+?)\s+\w+=""",
      """\sshost=({src_host}[^\s]+)\s""",
      """\ssuser=({user_fullname}.+?)\s+\w+=""",
      """\ssuid=LDAP:\/\/\S+\s+({user_ou}[^\/]+?)\/.+?\s+\w+=""",
      """\scs6=(?:-|({web_domain}.+?))\s\w+="""
  ]
  }
```