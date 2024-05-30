# A41 - MediTrack Project Read Me


## Team

| Number   | Name                | User                               | E-mail                                   |
| -------  | ------------------- | ---------------------------------- | ---------------------------------------- |
| 110890   | Rui Martins         | <https://github.com/RuiMartins05>  | <rui.ladeira.martins@tecnico.ulisboa.pt> |
| 110976   | Paulo Bolinhas      | <https://github.com/paulobolinhas> | <paulo.bolinhas@tecnico.ulisboa.pt>      |
| 99323    | Rui Moniz           | <https://github.com/RuiMFMoniz>    | <rui.moniz@tecnico.ulisboa.pt>           |

## Contents

This repository contains documentation and source code for the *Network and Computer Security (SIRS)* project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project.
It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

## Installation

To see the project in action, it is necessary to setup a virtual environment, with 2 networks (sw-1 and sw-2) and 3 machines (VM1,VM2 and VM3). 
The interfaces should be configured in a VM Manager but to configure the rest you just need to run the `init-vm`{machine number}`.sh` script for each machine

The following diagram shows the networks and machines:

![image](https://github.com/tecnico-sec/a41-paulo-rui-rui/assets/82532379/90383569-c9c2-4856-9e4c-06794ac05f0f)


### Prerequisites

All the virtual machines are based on: Linux 64-bit, Kali 2023.3  

[Download](https://turbina.gsd.inesc-id.pt/csf2324/resources/kali-linux-2023.2a-installer-amd64.iso) a virtual machine of Kali Linux 2023.3 from IST  
Clone the base machine to create the other machines and manually configure the interfaces described before.

### Machine configurations

For each machine, there is an initialization script with the machine number, `init-vm`{machine number}`.sh`, that installs all the necessary packages and makes all required configurations in the a clean machine.

Inside each machine, use Git to obtain a copy of all the scripts and code.

```sh
$ git clone https://github.com/tecnico-sec/a41-paulo-rui-rui.git
```

Next we have custom instructions for each machine.

#### Machine 1 - VM1

This machine runs a client Java 17 node which could represent a Patient, a Doctor, or an Insurance Company.

- Doctor:
- To Verify
```sh
$ mvn exec:java -Dexec.mainClass="domain.entities.Doctor"
```
Expected Result:
```
Choose your profile: 
1. Dr.Smith, Orthopedy
2. Dr.Jones, Emergency
```

- Patient:
- To Verify
```sh
$ mvn exec:java -Dexec.mainClass="domain.entities.Patient"
```
Expected Result:
```
Enter username:
```
- Insurance Company:
- To verify
```sh
$ mvn exec:java -Dexec.mainClass="domain.entities.InsuranceCompany"
```
Expected Result
```
Choose your profile: 
1. Freedom
```

####  Machine 2 - VM2

This machine runs a Server Java 17 node.

To verify:

```sh
$ mvn exec:java -Dexec.mainClass="domain.Server"
```
Expected Result
```
Waiting for client connections...
```

####  Machine 3 - VM3

This machine runs a Database Java 17 node.

To verify:

```sh
$ mvn exec:java -Dexec.mainClass="domain.DataBase"
```
Expected Result
```
Database waiting for connections...
```

## Testing

In order to test our machines' network configuration, a simple test can be made:
- In VM3 start the database with the command given earlier;
- In VM2 start the server with the command given earlier;
- In VM1 start the doctor app with the command given earlier;
- Choose one of the two doctor profiles;
- Choose option 'Create Record':
- Fill in the information requested;
- If the doctor application prints out 'Record created successfully!', then operation was successfull, which means both client-server and server-database
  connections are working as intended
## Demonstration

Now that all the networks and machines are up and running, let's see how the system operates.

First, start the database in VM3 and the server in VM2 (like we already shown). In VM1 open 4 terminals, to emulate 4 different users: a patient, both doctors in the system and an insurance company. To show the full capabilities of the application, proceed as follows:

- In one of the doctors, choose 'Create Record' and fill the information needed;

  
![Captura de ecrã 2023-12-21 011542](https://github.com/tecnico-sec/a41-paulo-rui-rui/assets/107137952/7ed523f7-af29-470c-a342-6aa12e68013f)


- Log in the patient account by entering the username for the new record;

 
![Captura de ecrã 2023-12-21 011812](https://github.com/tecnico-sec/a41-paulo-rui-rui/assets/107137952/ad84ef4a-eacb-47d5-a4e3-ec84524b5bae)


- In each of the doctors, choose 'Add consultation record' to add new consults to the previous record;

 
![Captura de ecrã 2023-12-21 011950](https://github.com/tecnico-sec/a41-paulo-rui-rui/assets/107137952/44728bab-160a-475d-82d7-038c8d4ce62b)


With this setup, the most interesting part of our application can be shown, which is the different ways a user can receive the same record, based on
what they are and what their circumstances are

- In the patient, choose 'See record'. The record will appear as plain text;
- In one of the doctors, choose 'Search record', enter the patient's username and choose 'Public view'.


![as](https://github.com/tecnico-sec/a41-paulo-rui-rui/assets/107137952/dd460638-5f35-4c3f-b514-e5999bff46e8)


  See how the medical information in the consultation record from his speciality is cleared, but everything else (except for the information always
  available, like the name) is encrypted. Do the same for the other doctor to see the diference;
- In the emergency doctor, instead of 'Public View' choose 'Emergency View'. See how the record is now fully revealed, as the emergency condition is triggered;
- In the insuranceCompany, choose 'Search record', enter the patient's username and choose 'Public view'. Notice how its similar to the doctor's case, but this
  time the consult information is financial related, instead of medical related;
- Finally, in the patient choose 'Grant access', choose "Doctor" and enter the name of one of the doctors. Do the same for the insurance company.


  ![Captura de ecrã 2023-12-21 013728](https://github.com/tecnico-sec/a41-paulo-rui-rui/assets/107137952/858517a3-1211-4530-ab7d-c4ccc50a8bbc)


- For the doctor and the insurance company, choose 'Search record', but this time pick the authorized view. See how the record appears the same way as before, but
  now emergency information (like knownIllnesses or bloodType) is liberated;
- Finally, in one of the doctors choose 'Remove Record' and enter the patient's username. See in the database VM that the files are no longer stored in directory Views

This concludes the demonstration.


## Additional Information

### Links to Used Tools and Libraries

- [Java 17.0.6](https://openjdk.java.net/)
- [Maven 3.8.1](https://maven.apache.org/)
- [Java Key Tool](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html)
- [Java.net.ssl](https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/package-summary.html)
- [com.google.gson](https://javadoc.io/doc/com.google.code.gson/gson/latest/com.google.gson/module-summary.html)
- [java.security](https://docs.oracle.com/javase/8/docs/api/java/security/package-summary.html)
- [javax.crypto](https://docs.oracle.com/javase/8/docs/api/javax/crypto/package-summary.html)

### Versioning

We use [SemVer](http://semver.org/) for versioning.  

### License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) for details.

----
