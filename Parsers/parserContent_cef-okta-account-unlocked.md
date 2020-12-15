#### Parser Content
```Java
{
Name = cef-okta-account-unlocked
  DataType = "account-unlocked"
  Conditions = ["""CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Okta""", """"eventType":"user.account.reset_password""""]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """target(s)?"+:[^\]]+?"+type"+:"+User"+[^\]\}]+?"+(alternateId|emailAddress)"+:(null|"+({target_user}[^"@]+@({target_domain}[^"]+)))""",
    """target(s)?"+:[^\]]+?"+type"+:"+User"+[^\]\}]+?"+(alternateId|emailAddress)"+:(null|"+(({target_domain}[^\\\/]+)[\/\\]+)?({target_user}[^"]+))"""
  ]
}
```