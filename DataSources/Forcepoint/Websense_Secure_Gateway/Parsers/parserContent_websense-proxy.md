#### Parser Content
```Java
{
Name = websense-proxy
  Conditions = [ """|Websense|Security|""","""cs3Label=ContentType"""]
  Fields = ${WPParserTemplates.wp-web-activity.Fields} [
      """\ssuser=(-|(?!LDAP:)({user}.+?))\s\w+=""",
      """\ssuser=LDAP:\/\/\S+\s+({user_ou}[^\/]+?)\/(System|({user_fullname}[^,]+?))\s+\w+=""",
      """\ssuser=LDAP:\/\/\S+\s+({user_ou}[^\/]+?)\/({user_lastname}[^,\\]+?)\\?,\s*({user_firstname}[^\\,]+?)\s+\w+=""",
      """\sdhost=(?:-|({web_domain}.+?))\s\w+=""",
      """\scs4=({category}.+?)\s+\w+=""",
      """\|Websense\|([^|]+\|){2}({category_id}[^|]+)""",
      """\sdhost=(.*?)({top_domain}[^.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ms))+\s\w+=).+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "user->orig_user" ]
  }
```