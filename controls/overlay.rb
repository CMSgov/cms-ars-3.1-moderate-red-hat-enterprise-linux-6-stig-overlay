# encoding: utf-8

include_controls 'Red Hat Enterprise Linux 6 Security Technical Implementation Guide' do


  control 'V-38477' do
    desc 'check', 'To check the minimum password age, run the command: 

         $ grep PASS_MIN_DAYS /etc/login.defs

         The CMS requirement is 1. 

         If it is not set to the required value, this is a finding.'
    desc 'fix', 'To specify password minimum age for new accounts, edit the file 
         "/etc/login.defs" and add or correct the following line, replacing [DAYS] 
         appropriately: 

         PASS_MIN_DAYS [DAYS]

         A value of 1 day is considered sufficient for many environments. The CMS 
         requirement is 1.'
  end
  
  control 'V-38479' do
    desc 'check', 'To check the maximum password age, run the command: 

         $ grep PASS_MAX_DAYS /etc/login.defs

         The CMS requirement is 60. 

         If it is not set to the required value, this is a finding.'
    desc 'fix', 'To specify password maximum age for new accounts, edit the file 
         "/etc/login.defs" and add or correct the following line, replacing [DAYS] 
         appropriately: 

         PASS_MAX_DAYS [DAYS]

         The CMS requirement is 60.'
  end

  control 'V-38480' do
    desc 'check', 'To check the password warning age, run the command: 

         $ grep PASS_WARN_AGE /etc/login.defs

         The CMS requirement is 7. 

         If it is not set to the required value, this is a finding.'
    desc 'fix',	'To specify how many days prior to password expiration that a warning 
         will be issued to users, edit the file "/etc/login.defs" and add or correct 
         the following line, replacing [DAYS] appropriately: 

         PASS_WARN_AGE [DAYS]

         The CMS requirement is 7.'
  end

  control 'V-38482' do
    desc 'check', 'To check how many digits are required in a password, run the 
         following command: 

         $ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

         Note: The "dcredit" parameter (as a negative number) will indicate how many 
         digits are required. CMS requires at least one digit in a password. This 
         would appear as "dcredit=-1". 

         If dcredit is not found or not set to the required value, this is a finding.'
  end

  control 'V-38492' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related 
         security control is not included in CMS ARS 3.1'
  end

  control 'V-38494' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related                                                      
         security control is not included in CMS ARS 3.1'
  end

  control 'V-38501' do
    desc 'title', 'The system must disable accounts after excessive login failures 
         within a 120-minute interval.'
    desc 'check', 'To ensure the failed password attempt policy is configured correctly, 
         run the following command:

         $ grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

         For each file, the output should show "fail_interval=<interval-in-seconds>" 
         where "interval-in-seconds" is 7200 (120 minutes) or greater. 
         
         If that is not the case, this is a finding.'
    desc 'fix', 'Utilizing "pam_faillock.so", the "fail_interval" directive configures 
         the system to lock out accounts after a number of incorrect logon attempts. 
         Modify the content of both "/etc/pam.d/system-auth" and 
         "/etc/pam.d/password-auth" as follows: 

         Add the following line immediately before the "pam_unix.so" statement in the 
         "AUTH" section: 

         auth required pam_faillock.so preauth silent deny=5 unlock_time=3600 fail_interval=7200

         Add the following line immediately after the "pam_unix.so" statement in the "AUTH" 
         section: 

         auth [default=die] pam_faillock.so authfail deny=5 unlock_time=3600 fail_interval=7200

         Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" 
         section: 

         account required pam_faillock.so

         Note that any updates made to "/etc/pam.d/system-auth" and 
         "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The 
         "authconfig" program should not be used.'
  end

  control 'V-38569' do
    desc 'title', 'The system must require passwords to contain at least one uppercase 
         alphabetic characters.'
    desc 'check', 'To check how many uppercase characters are required in a password, run 
         the following command: 

         $ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

         Note: The "ucredit" parameter (as a negative number) will indicate how many 
         uppercase characters are required. CMS requires at least one uppercase character 
         in a password. This would appear as "ucredit=-1". 

If ucredit is not found or not set to the required value, this is a finding.'
    desc 'fix', 'The pam_cracklib module\'s "ucredit=" parameter controls requirements for 
         usage of uppercase letters in a password. When set to a negative number, any 
         password will be required to contain that many uppercase characters. When set to 
         a positive number, pam_cracklib will grant +1 additional length credit for each 
         uppercase character. 

         Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding ""ucredit=-1"" 
         after pam_cracklib.so to require use of an uppercase character in passwords."'
  end

  control 'V-38570' do
    desc 'tite', 'The system must require passwords to contain at least one special 
         character.'
    desc 'check', 'To check how many special characters are required in a password, 
         run the following command: 

         $ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

         Note: The "ocredit" parameter (as a negative number) will indicate how many 
         special characters are required. CMS requires at least one special character 
         in a password. This would appear as "ocredit=-1". 

         If ocredit is not found or not set to the required value, this is a finding.'
    desc 'fix', 'The pam_cracklib module\'s "ocredit=" parameter controls requirements 
         for usage of special (or "other") characters in a password. When set to a 
         negative number, any password will be requied to contain that many special 
         characters. When set to a positive number, pam_cracklib will grant +1 
         additional length credit for each special character. 

         Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "ocredit=-1" 
         after pam_cracklib.so to require use of a special character in passwords.'
  end

  control 'V-38571' do
    desc 'title', 'The system must require passwords to contain at least one lower-case 
         alphabetic character.'
    desc 'check', 'To check how many lower-case characters are required in a password, 
         run the following command: 
         
         $ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

         Note: The "lcredit" parameter (as a negative number) will indicate how many 
         lower-case characters are required. CMS requires at least one lower-case 
         character in a password. This would appear as "lcredit=-1". 

         If lcredit is not found or not set to the required value, this is a finding.'
    desc 'fix', 'The pam_cracklib module\'s "lcredit=" parameter controls requirements 
         for usage of lower-case letters in a password. When set to a negative number, 
         any password will be required to contain that many lower-case characters. 

         Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "lcredit=-1" 
         after pam_cracklib.so to require use of a lower-case character in passwords.'
  end

  control 'V-38572' do
    desc 'title', 'The system must require at least six characters be changed between 
         the old and new passwords during a password change.'
    desc 'check', 'To check how many characters must differ during a password change, 
         run the following command: 

         $ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

         Note: The "difok" parameter will indicate how many characters must differ. 
         CMS requires that six characters differ during a password change. This would 
         appear as "difok=6". 
         
         If difok‚ is not found or is set to a value less than‚ 6, this is a finding.'
    desc 'fix', 'The pam_cracklib module\'s "difok" parameter controls requirements 
         for usage of different characters during a password change.

         Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "difok=[NUM]" 
         after pam_cracklib.so to require differing characters when changing passwords, 
         substituting [NUM] appropriately. The CMS requirement is 6.'
  end

  control 'V-38573' do
    desc 'title', 'The system must disable accounts after five consecutive 
         unsuccessful logon attempts.'
    desc 'check', 'To ensure the failed password attempt policy is configured correctly, 
         run the following command: 

         # grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

         The output should show "deny=5" for both files. 

         If that is not the case, this is a finding.'
    desc 'fix', 'To configure the system to lock out accounts after a number of 
         incorrect logon attempts using "pam_faillock.so", modify the content of both 
         "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 

         Add the following line immediately before the "pam_unix.so" statement in 
         the "AUTH" section: 

         auth required pam_faillock.so preauth silent deny=5 unlock_time=3600 fail_interval=7200

         Add the following line immediately after the "pam_unix.so" statement in the 
         "AUTH" section: 

         auth [default=die] pam_faillock.so authfail deny=5 unlock_time=3600 fail_interval=7200

         Add the following line immediately before the "pam_unix.so" statement in the 
         "ACCOUNT" section: 

         account required pam_faillock.so

         Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" 
         may be overwritten by the "authconfig" program.  The "authconfig" program should not 
         be used.'
  end

  control 'V-38592' do
    title 'The system must require an account to be locked out for at least an hour for an account 
    locked by excessive failed login attempts.'

    desc 'Locking out user accounts after a number of incorrect attempts prevents direct password 
    guessing attacks.'

    desc 'check', 'To ensure the failed password attempt policy is configured correctly, run the 
    following command: 

    # grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

    The output should show "unlock_time=1800" or higher.

    If that is not the case, this is a finding.'

    desc 'fix', 'To configure the system to lock out accounts after a number of incorrect 
    logon attempts and require an administrator to unlock the account using "pam_faillock.so", 
    modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 
    
    Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section: 

    auth required pam_faillock.so preauth silent deny=3 unlock_time=1800 fail_interval=900

    Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section: 

    auth [default=die] pam_faillock.so authfail deny=3 unlock_time=1800 fail_interval=900

    Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section: 

    account required pam_faillock.so

    Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may 
    be overwritten by the "authconfig" program.  The "authconfig" program should not be used.'
  end

  control 'V-38593' do
    desc 'title', 'The CMS login banner must be displayed immediately prior to, or as part of, 
         console login prompts.'
    desc 'check', 'To check if the system login banner is compliant, run the following command: 

         $ cat /etc/issue

         Note: The full text banner must be implemented unless there are character limitations 
         that prevent the display of the full CMS logon banner.

         If the required CMS logon banner is not displayed, this is a finding.'
    desc 'fix', 'To configure the system login banner: 

         Edit "/etc/issue". Replace the default text with a message compliant with the local 
         site policy or a legal disclaimer. The DoDCMS required text is either: 

         The approved banner states:

         * This warning banner provides privacy and security notices consistent with applicable 
         federal laws, directives, and other federal guidance for accessing this Government system, 
         which includes (1) this computer network, (2) all computers connected to this network, 
         and (3) all devices and storage media attached to this network or to a computer on this network.
         * This system is provided for Government authorized use only.
         * Unauthorized or improper use of this system is prohibited and may result in disciplinary 
         action and/or civil and criminal penalties.
         * Personal use of social media and networking sites on this system is limited as to not 
         interfere with official work duties and is subject to monitoring.
         * By using this system, you understand and consent to the following:
         - The Government may monitor, record, and audit your system usage, including usage of 
         personal devices and email systems for official duties or to conduct HHS business. Therefore, 
         you have no reasonable expectation of privacy regarding any communication or data transiting 
         or stored on this system. At any time, and for any lawful Government purpose, the government 
         may monitor, intercept, and search and seize any communication or data transiting or stored 
         on this system.
         - Any communication or data transiting or stored on this system may be disclosed or used for 
         any lawful Government purpose'
  end

  control 'V-38608' do
    desc 'check', 'Run the following command to see what the timeout interval is: 

         # grep ClientAliveInterval /etc/ssh/sshd_config
         
         If properly configured, the output should be: 

         ClientAliveInterval 1800

         If it is not, this is a finding.'
    desc 'fix', 'SSH allows administrators to set an idle timeout interval. After 
         this interval has passed, the idle user will be automatically logged out. 

         To set an idle timeout interval, edit the following line in "/etc/ssh/sshd_config" as follows: 

         ClientAliveInterval [interval]

         The timeout [interval] is given in seconds. To have a timeout of 30 minutes, set [interval] 
         to 1800. 

         If a shorter timeout has already been set for the login shell, that value will preempt any 
         SSH setting made here. Keep in mind that some processes may stop SSH from correctly 
         detecting that the user is idle.'
  end

  control 'V-38610' do
    tag "cci": ['CCI-002361']
    tag "nist": ['AC-12', 'Rev_4']
  end

  control 'V-38611' do
    tag "cci": ['CCI-000366']
    tag "nist": ['CM-6 b', 'Rev_4']
  end

  control 'V-38612' do
    tag "cci": ['CCI-000366']
    tag "nist": ['CM-6 b', 'Rev_4']
  end

  control 'V-38615' do
    desc 'title', 'The SSH daemon must be configured with the CMS login banner.'
  end

  control 'V-38621' do
    desc 'title', 'The system clock must be synchronized to an authoritative DCMS 
         time source.'
  end

  control 'V-38658' do
    title 'The system must prohibit the reuse of passwords within 6 iterations.'

    desc 'check', 'To verify the password reuse setting is compliant, run the 
    following command:

    # grep remember /etc/pam.d/system-auth /etc/pam.d/password-auth

    If the line is commented out, the line does not contain "password required pam_pwhistory.so" 
    or "password requisite pam_pwhistory.so", or the value for "remember" is less than ‚ 6, 
    this is a finding.'

    desc 'fix', 'Do not allow users to reuse recent passwords. This can be accomplished by using 
    the "remember" option for the "pam_pwhistory" PAM module. In the file "/etc/pam.d/system-auth" 
    and /etc/pam.d/password-auth, append "remember=6" to the lines that refer to the "pam_pwhistory.so" 
    module, as shown:

    password required pam_pwhistory.so [existing_options] remember=6

    or

    password requisite pam_pwhistory.so [existing_options] remember=6

    The CMS requirement is 6 passwords.'
  end

  control 'V-38681' do
    tag "cci": ['CCI-000764']
    tag "nist": ['IA-2', 'Rev_4']
  end

  control 'V-38685' do
    desc 'check', 'For every temporary account, run the following command to obtain 
         its account aging and expiration information: 

         # chage -l [USER]

         Verify each of these accounts has an expiration date set at 30 days from creation. 
         If any temporary accounts have no expiration date set or do not expire within 
         30 days, this is a finding.'
    desc 'fix', 'In the event temporary accounts are required, configure the system to 
         terminate them after 30 days. For every temporary account, run the following 
         command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" 
         appropriately: 

         # chage -E [YYYY-MM-DD] [USER]

         "[YYYY-MM-DD]" indicates the documented expiration date for the account.'
  end

  control 'V-38689' do
    desc 'title', 'The CMS login banner must be displayed immediately prior to, or as part of, 
         graphical desktop environment login prompts.'
    desc 'check', ''
    desc 'fix', 'If the GConf2 package is not installed, this is not applicable.

         To ensure login warning banner text is properly set, run the following: 

         $ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory 
                       --get /apps/gdm/simple-greeter/banner_message_text

         If properly configured, the proper banner text will appear within this schema. 

         The approved banner states: 

         "* This warning banner provides privacy and security notices consistent with applicable 
         federal laws, directives, and other federal guidance for accessing this Government system, 
         which includes (1) this computer network, (2) all computers connected to this network, 
         and (3) all devices and storage media attached to this network or to a computer on this 
         network.
         * This system is provided for Government authorized use only.
         * Unauthorized or improper use of this system is prohibited and may result in disciplinary 
         action and/or civil and criminal penalties.
         * Personal use of social media and networking sites on this system is limited as to not 
         interfere with official work duties and is subject to monitoring.
         * By using this system, you understand and consent to the following:
         - The Government may monitor, record, and audit your system usage, including usage of 
         personal devices and email systems for official duties or to conduct HHS business. 
         Therefore, you have no reasonable expectation of privacy regarding any communication or 
         data transiting or stored on this system. At any time, and for any lawful Government purpose, 
         the government may monitor, intercept, and search and seize any communication or data 
         transiting or stored on this system.
         - Any communication or data transiting or stored on this system may be disclosed or used for 
         any lawful Government purpose" 
         
         If the CMS required banner text does not appear in the schema, this is a finding.'

    desc 'fix', 'To set the text shown by the GNOME Display Manager in the login screen, run the 
         following command: 

         # gconftool-2
         --direct \
         --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
         --type string \
         --set /apps/gdm/simple-greeter/banner_message_text \
         "[CMS required text]"
         
         The approved banner states:
         "* This warning banner provides privacy and security notices consistent with applicable 
         federal laws, directives, and other federal guidance for accessing this Government system, 
         which includes (1) this computer network, (2) all computers connected to this network, and 
         (3) all devices and storage media attached to this network or to a computer on this network.
         * This system is provided for Government authorized use only.
         * Unauthorized or improper use of this system is prohibited and may result in disciplinary 
         action and/or civil and criminal penalties.
         * Personal use of social media and networking sites on this system is limited as to not 
         interfere with official work duties and is subject to monitoring.
         * By using this system, you understand and consent to the following:
         - The Government may monitor, record, and audit your system usage, including usage of 
         personal devices and email systems for official duties or to conduct HHS business. Therefore, 
         you have no reasonable expectation of privacy regarding any communication or data transiting 
         or stored on this system. At any time, and for any lawful Government purpose, the government 
         may monitor, intercept, and search and seize any communication or data transiting or stored 
         on this system.
         - Any communication or data transiting or stored on this system may be disclosed or used for 
         any lawful Government purpose"

         When entering a warning banner that spans several lines, remember to begin and end the string 
         with """. This command writes directly to the file 
         "/etc/gconf/gconf.xml.mandatory/apps/gdm/simple-greeter/%gconf.xml", and this file can later 
         be edited directly if necessary.'
  end

  control 'V-38690' do
    desc 'title', 'Emergency accounts must be provisioned with an expiration date of 24 hours.'
    desc 'check', 'For every emergency account, run the following command to obtain its account aging 
         and expiration information: 

         # chage -l [USER]

         Verify each of these accounts has an expiration date set within 24 hours of being created. 
         If any emergency accounts have no expiration date set or do not expire within a documented time 
         frame, this is a finding.'
  end

  control 'V-38692' do
    desc 'title', 'Accounts must be locked upon 60 days of inactivity.'
    desc 'check', 'To verify the "INACTIVE" setting, run the following command: 

         grep "INACTIVE" /etc/default/useradd

         The output should indicate the "INACTIVE" configuration option is set to an appropriate integer 
         as shown in the example below: 

         # grep "INACTIVE" /etc/default/useradd
         INACTIVE=60

         If it does not, this is a finding.'
    desc 'fix', 'To specify the number of days after a password expires (which signifies inactivity) 
         until an account is permanently disabled, add or correct the following lines in 
         "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately: 

         INACTIVE=[NUM_DAYS]

         A value of 60 is recommended. If a password is currently on the verge of expiration, then 
         60 days remain until the account is automatically disabled. However, if the password will 
         not expire for another 60 days, then 120 days could elapse until the account would be 
         automatically disabled. See the "useradd" man page for more information. Determining the 
         inactivity timeout must be done with careful consideration of the length of a "normal" period 
         of inactivity for users in the particular environment. Setting the timeout too low incurs 
         support costs and also has the potential to impact availability of the system to legitimate 
         users.'
  end

  control 'V-38693' do
     impact 'none'
     desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related                                                     
          security control is not included in CMS ARS 3.1'         
  end

  control 'V-38694' do
    desc 'check', 'To verify the "INACTIVE" setting, run the following command: 

         grep "INACTIVE" /etc/default/useradd

         The output should indicate the "INACTIVE" configuration option is set to an appropriate 
         integer as shown in the example below: 

         # grep "INACTIVE" /etc/default/useradd
         INACTIVE=60

         If it does not, this is a finding.'
    desc 'fix', 'To specify the number of days after a password expires (which signifies inactivity) 
         until an account is permanently disabled, add or correct the following lines in 
         "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately: 

         INACTIVE=[NUM_DAYS]

         A value of 60 is recommended. If a password is currently on the verge of expiration, then 
         30 days remain until the account is automatically disabled. However, if the password will 
         not expire for another 60 days, then 120 days could elapse until the account would be 
         automatically disabled. See the "useradd" man page for more information. Determining the 
         inactivity timeout must be done with careful consideration of the length of a "normal" 
         period of inactivity for users in the particular environment. Setting the timeout too 
         low incurs support costs and also has the potential to impact availability of the system 
         to legitimate users.'
  end
end
