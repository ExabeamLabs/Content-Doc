#### Parser Content
```Java
{
Name = quest-change-account-lockout
     DataType = "windows-account-lockout"
     Conditions = [ """CEF:""", """Quest Software""", """|Change Auditor|""", """|Active Directory|""",  """User account locked"""  ]	 
}
```