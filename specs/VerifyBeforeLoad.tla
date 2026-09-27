---- MODULE VerifyBeforeLoad ----
EXTENDS Naturals, Integers, FiniteSets, TLC

CONSTANTS Design, Actors, MaxVersion
VARIABLES fileContent, fileVersion, openVersion, openedContent, verified, loaded, cacheValid,
          cacheVersion, badLoaded

Contents == {"good", "bad"}
NoHandle == -1

Init ==
  /\ fileContent = "good"
  /\ fileVersion = 0
  /\ openVersion = [a \in Actors |-> NoHandle]
  /\ openedContent = [a \in Actors |-> "none"]
  /\ verified = [a \in Actors |-> FALSE]
  /\ loaded = [a \in Actors |-> FALSE]
  /\ cacheValid = FALSE
  /\ cacheVersion = NoHandle
  /\ badLoaded = FALSE

Modify ==
  /\ fileVersion < MaxVersion
  /\ fileVersion' = fileVersion + 1
  /\ fileContent' \in Contents
  /\ UNCHANGED <<openVersion, openedContent, verified, loaded, cacheValid, cacheVersion, badLoaded>>

Open(a) ==
  /\ openVersion' = [openVersion EXCEPT ![a] = fileVersion]
  /\ openedContent' = [openedContent EXCEPT ![a] = fileContent]
  /\ verified' = [verified EXCEPT ![a] = FALSE]
  /\ loaded' = [loaded EXCEPT ![a] = FALSE]
  /\ UNCHANGED <<fileContent, fileVersion, cacheValid, cacheVersion, badLoaded>>

Verify(a) ==
  /\ openVersion[a] # NoHandle
  /\ verified' = [verified EXCEPT ![a] = (openedContent[a] = "good")]
  /\ UNCHANGED <<fileContent, fileVersion, openVersion, openedContent, loaded,
                 cacheValid, cacheVersion, badLoaded>>

CacheStore ==
  /\ fileContent = "good"
  /\ cacheValid' = TRUE
  /\ cacheVersion' = fileVersion
  /\ UNCHANGED <<fileContent, fileVersion, openVersion, openedContent, verified, loaded, badLoaded>>

CacheUse(a) ==
  /\ cacheValid
  /\ cacheVersion = fileVersion
  /\ fileContent = "good"
  /\ verified' = [verified EXCEPT ![a] = TRUE]
  /\ openVersion' = [openVersion EXCEPT ![a] = fileVersion]
  /\ openedContent' = [openedContent EXCEPT ![a] = fileContent]
  /\ UNCHANGED <<fileContent, fileVersion, loaded, cacheValid, cacheVersion, badLoaded>>

LoadNaive(a) ==
  /\ Design = "naive"
  /\ verified[a]
  /\ loaded' = [loaded EXCEPT ![a] = TRUE]
  /\ badLoaded' = (badLoaded \/ (fileContent = "bad"))
  /\ UNCHANGED <<fileContent, fileVersion, openVersion, openedContent, verified,
                 cacheValid, cacheVersion>>

LoadSafe(a) ==
  /\ Design = "safe"
  /\ verified[a]
  /\ loaded' = [loaded EXCEPT ![a] = TRUE]
  /\ badLoaded' = (badLoaded \/ (openedContent[a] = "bad"))
  /\ UNCHANGED <<fileContent, fileVersion, openVersion, openedContent, verified,
                 cacheValid, cacheVersion>>

Next ==
  Modify \/ CacheStore \/ (\E a \in Actors: Open(a) \/ Verify(a) \/ CacheUse(a) \/ LoadNaive(a) \/ LoadSafe(a))

NoBadLoad == ~badLoaded
TypeOK ==
  /\ fileContent \in Contents
  /\ fileVersion \in 0..MaxVersion
  /\ openVersion \in [Actors -> {NoHandle} \cup (0..MaxVersion)]
  /\ openedContent \in [Actors -> Contents \cup {"none"}]
  /\ verified \in [Actors -> BOOLEAN]
  /\ loaded \in [Actors -> BOOLEAN]
  /\ cacheValid \in BOOLEAN
  /\ cacheVersion \in {NoHandle} \cup (0..MaxVersion)
  /\ badLoaded \in BOOLEAN
====
