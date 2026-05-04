**DEPARTMENT OF COMPUTING  
**

**CS-360: Cyber Security**

**Class: BSCS-2K23**

**Lab 11: Open Ended Lab**

**CLO-3:** Students will be able to perform practical technical tasks by following, applying, and demonstrating guided procedures and techniques in supervised laboratory or training environments.

**Date: 14th April 2026**

**Time: 10:00 - 12:50 / 14:00 - 16:50**

**Lab Instructor: Ms. Hadia Tahir**

**Class Instructor: Dr. Madiha Khalid**

**Lab 11: Open Ended Lab**

**Introduction:**

In modern cybersecurity, protecting cryptographic systems against real-world attacks goes beyond theoretical security. Even highly secure algorithms can leak sensitive information through physical side channels such as power consumption, timing behavior, and electromagnetic emissions. This field of study, known as _Side-Channel Analysis (SCA)_**_,_** has become a critical area in both academic research and practical security evaluation.

In this lab, students will explore side-channel vulnerabilities in a real-world, NIST-standardized lightweight cryptographic algorithm: _ASCON_. Unlike previous labs that provided structured guidance and simplified scenarios, this Open-Ended Lab challenges students to independently apply their knowledge to a complex and practical system.

ASCON represents a modern approach to lightweight cryptography, specifically designed for resource-constrained environments such as IoT devices and embedded systems. Despite its strong theoretical security, its implementation may still be susceptible to side-channel leakage, making it an ideal candidate for practical analysis.

This lab integrates concepts from previous experiments—including deep learning-based side-channel attacks, trace generation, and end-to-end attack pipelines—into a comprehensive project. Students will implement the ASCON cipher, simulate its execution to collect power traces, and apply machine learning techniques to recover secret key information.

The goal of this lab is not only to perform an attack but to develop independent problem-solving, research skills, and critical thinking**,** mirroring real-world cybersecurity and cryptographic research workflows. By the end of this lab, students will gain hands-on experience in analyzing and evaluating the security of modern cryptographic systems under realistic conditions.

**Project Overview**

This Open-Ended Lab extends concepts from previous labs (deep learning-based SCA, trace generation, and end-to-end attacks) to a standardized lightweight cipher: ASCON.

Students will perform a complete end-to-end side-channel attack workflow, including:

*   Understanding and analyzing the ASCON-128 cipher
*   Implementing the algorithm in C
*   Generating simulated power traces using the Rainbow framework
*   Designing deep learning models to recover secret key information

The project is designed to replicate a real-world cryptographic attack pipeline, where no step-by-step instructions are provided, and students must independently determine implementation strategies.

**Learning Objectives**

By completing this Open-Ended Lab, students will:

*   Independently research and understand a complex cryptographic standard (ASCON)
*   Implement authenticated encryption algorithm from specification
*   Apply reverse engineering skills to understand cipher internals
*   Design and implement trace generation for a real-world cipher
*   Create research-grade side-channel analysis datasets
*   Architect deep learning models for SCA without templates
*   Demonstrate problem-solving skills in complex security scenarios
*   Experience realistic cryptographic research workflow
*   Develop technical writing skills through comprehensive documentation
*   Build confidence in independent technical work

**Tools/ Software Requirements**

*   Ubuntu/Kali Linux system
*   Python 3.8+ with TensorFlow, NumPy, h5py
*   Rainbow framework (already installed from Lab 07)
*   ARM GCC toolchain for compilation

**ASCON:**

ASCON is a family of lightweight cryptographic algorithms designed for secure communication in resource-constrained environments such as IoT devices and embedded systems.

**Key Highlights:**

*   Selected as the NIST Lightweight Cryptography Standard (2023)
*   Winner of the CAESAR competition (2019)
*   Designed for efficiency, security, and low resource usage

**Core Features:**

*   Supports Authenticated Encryption with Associated Data (AEAD)
*   Based on a sponge construction
*   Uses a 320-bit internal state (5 × 64-bit words)
*   Employs a non-linear S-box and linear diffusion layer
*   Provides 128-bit security level

**Variants:**

*   **_Ascon-128_** → Standard version (used in this lab)
*   **_Ascon-128a_** → Faster variant
*   **_Ascon-Hash_** → Hashing function
*   **_Ascon-XOF_** → Extendable output function

Despite its strong theoretical design, ASCON implementations may still leak information through physical channels, making it a suitable target for side-channel attacks.

**Lab Tasks**

This project is divided into four major phases. Each phase builds upon the previous one and contributes to a complete end-to-end side-channel analysis of the ASCON-128 cipher.

**_Phase 1: Research and Understanding_**

In this phase, students will develop a strong conceptual understanding of the ASCON-128 cipher by studying its official specification and related resources.

You are expected to:

*   Carefully read the ASCON specification document and understand its structure
*   Analyze how _Authenticated Encryption with Associated Data (AEAD)_ works in ASCON
*   Study the _sponge construction_ and how data flows through different phases
*   Break down the _320-bit state representation (5 × 64-bit words)_
*   Understand the _permutation function_, including:
    *   Round constants
    *   Substitution layer (S-box)
    *   Linear diffusion layer
*   Identify _intermediate values_ where information leakage may occur (potential SCA attack points)

**_Deliverables (Phase 1):_**

*   _ASCON Study Report_ including:
    *   Overview of ASCON-128 cipher
    *   Explanation of AEAD mode
    *   Description of permutation and internal structure
    *   Identification of potential SCA leakage points

**_Phase 2: Implementation_**

In this phase, you will translate your theoretical understanding into a working implementation of ASCON-128.

You are expected to:

*   Implement the _ASCON-128 encryption algorithm in C_ from scratch
*   Represent and manage the _320-bit internal state efficiently_
*   Implement all major components:
    *   Initialization
    *   Permutation function
    *   S-box layer
    *   Linear diffusion layer
    *   Encryption and finalization
*   Ensure proper handling of padding, nonce, and key

After implementation:

*   Compile the code for _ARM Cortex-M3 architecture_
*   Verify correctness using test vectors or sample inputs
*   Debug and validate each component

**_Deliverables (Phase 2):_**

*   **C Source Code:**
    *   ascon128.c
*   **Compiled Binary:**
    *   ascon128.elf (ARM compiled file)
*   **Testing Evidence:**
    *   Screenshots or logs showing correct execution/results
*   **Technical Write-up:**
    *   Implementation approach
    *   Challenges faced and solutions
    *   Testing methodology

**_Phase 3: Trace Generation_**

In this phase, you will simulate execution to generate side-channel data. All traces must be generated using your Ascon-128 implementation only.

You are expected to:

*   Integrate your implementation with the _Rainbow framework_
*   Generate _power traces_ from simulated executions
*   Create two datasets:

**Fixed-Key Dataset:**

*   Same key, varying inputs
*   Profiling + Attack split

**Variable-Key Dataset:**

*   Different keys across traces
*   Ensure unseen keys in attack set

Additionally:

*   Apply a _leakage model_ (e.g., Hamming Weight)
*   Select a meaningful _intermediate target value_
*   Store datasets in _HDF5 format_
*   Validate and visualize traces

**_Deliverables (Phase 3):_**

*   **Trace Generation Script:**
    *   generate\_traces.py
*   **Dataset Documentation:**
    *   Trace generation process
    *   Leakage model explanation
    *   Target point selection
    *   Sample trace plots (at least 10)

**_Phase 4: Deep Learning Attack_**

In this phase, you will perform key recovery using machine learning.

You are expected to:

*   Define the _target variable_ for prediction
*   Generate labels based on your leakage model
*   Design and train a _neural network model_
*   Evaluate performance on both datasets

You must perform:

**Fixed-Key Attack:**

*   Recover key bytes
*   Measure success rate

**Variable-Key Attack:**

*   Evaluate model generalization
*   Compare with fixed-key results
*   Analyze limitations

Additionally:

*   Track training performance (loss, accuracy)
*   Perform _key rank analysis_
*   Interpret and explain results

**Deliverables (Phase 4):**

*   **Attack Scripts:**
    *   attack\_fixed\_key.py
    *   attack\_variable\_key.py
*   **Trained Models:**
    *   model\_fixed\_key.h5
    *   model\_variable\_key.h5
*   **Results & Analysis Report:**
    *   Model architecture and training details
    *   Attack performance (fixed vs variable key)
    *   Key recovery results
    *   Critical analysis and observations

**Grading Rubrics:**

| Assessment Area | CLO / PLO | Does Not Meet Expectation (0–1) | Meets Expectation (2–3) | Exceeds Expectation (4–5) | Score |
| --- | --- | --- | --- | --- | --- |
| Lab Preparation & Environment Setup | CLO 3GA-5(P-3) | Student fails to set up the required lab environment (e.g., Kali Linux, IBM Qiskit, or development tools); does not follow setup instructions; tools are missing, misconfigured, or non-functional before the lab begins. | Student correctly configures the required environment with minor issues (e.g., slight misconfiguration resolved with guidance); tools are mostly functional; lab can proceed with minimal disruption. | Student demonstrates confident, independent setup of the full environment; all tools (e.g., Wireshark, Qiskit, Metasploit, Docker) are correctly installed and ready prior to the lab; shows initiative in verifying tool versions and configurations. | / 2 |
| Execution of Lab Procedures & Tool Usage | CLO 3GA-5(P-3) | Student fails to correctly execute the required lab steps (e.g., running PowerShell scans, Qiskit circuits, OSINT tools, Blockchain deployment); solution does not run correctly or produces incorrect results with no meaningful attempt to debug. | Student successfully executes the core lab procedures; prescribed tools are used adequately; solution runs mostly correctly with minor issues in edge cases, command syntax, or output correctness. | Student demonstrates correct, precise execution of all lab steps; uses tools (e.g., Nmap, ForkJoin, Rainbow tables, BB84 Qiskit circuits) with full command mastery; handles edge cases and verifies outputs against expected results. | / 3 |
| Observations, Data Recording & Screenshots | CLO 3GA-5(P-3) | Student provides little to no recorded observations; screenshots are absent or irrelevant; results are not documented or are inconsistent with the lab task performed. | Student records most observations with adequate screenshots; minor omissions or annotation errors present; results are largely consistent with the expected lab outcome. | Student provides thorough, well-annotated documentation of all observations; screenshots are clearly labelled and directly linked to lab objectives (e.g., packet captures, side-channel traces, quantum measurement outputs, smart contract logs). | / 2 |
| Analysis & Security Insight | CLO 3GA-5(P-3) | Student offers no meaningful analysis of results; fails to identify vulnerabilities, attack vectors, or cryptographic properties; conclusions are absent or entirely incorrect. | Student identifies key findings with reasonable analysis; connects results to lab objectives (e.g., ASCON-128 resistance, eavesdropping detection in BB84, OSINT surface); minor gaps in depth or accuracy. | Student provides insightful, well-reasoned analysis; correctly interprets security implications (e.g., side-channel leakage in AES/ASCON, smart contract vulnerabilities, quantum eavesdropping); draws conclusions connecting results to theoretical course concepts. | / 2 |
| Lab Report Quality & Submission | CLO 3GA-5(P-3) | Report is poorly structured or not submitted; sections missing; writing is unclear; no references or citations; does not meet SEECS lab submission guidelines. | Report is complete and adequately organized; minor formatting or clarity issues; most sections present; submitted on time following lab guidelines. | Report is professionally written and well-structured; all sections complete with clear headings; follows SEECS submission guidelines; zero-plagiarism; references cited where applicable. | / 1 |