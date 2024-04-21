# Project: Encrypted Traffic Analysis

## Obsah:
  1. [Popis](#popis)
  2. [Instalace](#instalace)
  3. [Použití](#použití)

## Popis
Výsledkem projektu je natrénovaný model neuronové sítě, který vyhodnocuje, zda
je analyzovaná komunikace šifrovaná či nikoli. Celou aplikaci lze ovládat pomocí
grafického uživatelského rozhraní, jenž umožňuje nahrávat soubory ve formátu pcap
se zachycenou komunikací nebo nahrát novou komunikaci z předvoleného síťového
rozhraní. Aplikace si automaticky z poskytnuté komunikace získá potřebná data a
zaznamená je do nového souboru ve formátu csv. Z tohoto nově vytvořeného souboru
dojde k vyhodnocení zachycené komunikace pomocí natrénovaného modelu neuro-
nové sítě a vypracované výsledky jsou spolu se statistikami o komunikaci přehledně
zobrazeny v grafickém uživatelském rozhraní.

<img width="902" alt="GUI_design" src="https://github.com/lei1738/kry/assets/138430747/71866360-4709-4cc8-b08d-0e52e2681940">

## Instalace
<details>
  <summary>
    Krok 1: Stáhnout projekt
  </summary>
  - Z GitHubu / Místa odevzdání projektu na školních stránkách
</details>
<details>
  <summary>
    Krok 2: Nainstalovat python
  </summary>
   - Stáhnout python v3.12: https://www.python.org/downloads/
</details>
<details>
  <summary>
    Krok 3: Nainstalovat knihovny
  </summary>
  
  • **Pip** - využívané k instalaci knihoven
  
        python get-pip.py
  • **Pyshark (v0.6)** - využívané funkce jsou k zachycení síťové komunikace v pythonu
  
        pip install pyshark
  • **Scapy (v2.5.0)** - z knihovny je využívaná funkce PcapReader pro čtení z pcap souboru

        pip install scapy
  • **Pandas (v2.2.1)** - funkce pro čtení a práci s csv soubory

        pip install pandas
  • **OS** - funkce pro práci se systémovým adresářem a volání příkazů přes systémový terminál
      - automatickou součástí pythonu!
      
  • **Enum** - knihovna pro použití výčtového datového typu

        pip install enum
  • **Tkinter** - knihovna pro vytvoření GUI
      - automatickou součástí pythonu!
        
        pip install tk
  • **CustomTkinter (v5.2.2)** - knihovna pro GUI

        pip install customtkinter
  • **Tabulate (v0.9.0)** - knihovna pro práci s tabulkami

        pip install tabulate
  • **Sklearn (v1.4.2)** - knihovna pro strojové učení

        pip install scikit-learn
  • **Keras (v3.2.1)** - knihovna pro neuronové sítě

        pip install keras
  • **TensorFlow (v2.16.1)** - knihovna pro vytváření modelů strojového učení

        pip install tensorflow
  • **Sys** - knihovna pro volání systémových funkcí
        - automatickou součástí pythonu!
        
  • **Collections** - knihovna pro specializované kontejnerové datové typy
        - automatickou součástí pythonu!
  
  • **Psutil (v5.9.8)** - knihovna pro zisk informací o probíhajících procesech a využití systému
  
         pip install psutil 
  • **Csv** - knihovna pro čtení a zápis souborů ve formátu csv
        - automatickou součástí pythonu!
        
</details>
<details>
  <summary>
    Krok 4: Nainstalovat PyCharm
  </summary>
    - Stáhnout PyCharm: https://www.jetbrains.com/pycharm/
</details>
<details>
  <summary>
    Krok 5: Nastavení statické kryptografické soli
  </summary>
    - V programu PyCharm je třeba nastavit proměnou prostředí. Nastavení najdeme v pravé části okna vedle stratovacího tlačítka (viz. 1. obrázek). Dále klikneme na "Edit Configuration", které otevře nové okno s více nastaveními. U souboru GUI.py (vybereme v levem slloupci) nastavíme v poli "Enviromental variables" (viz. 2. obrázek níže) následující řetězec:
  
      PYTHONHASHSEED=0; PYTHONUNBUFFERED=1
      
  Může být třeba restartovat program PyCharm pro projevení změny.
  ![image](https://github.com/lei1738/kry/assets/138430747/6e8eb298-e6de-4cbb-be32-7fa1ffacd503)
  
  ![image](https://github.com/lei1738/kry/assets/138430747/8812e65b-d745-47c1-b684-16270a7acc50)

</details>
<details>
  <summary>
    Krok 6: Spustit GUI.py
  </summary>
    - Kliknutím pravým tlačítkem na soubor "GUI.py" se zobrazí nabídka akcí, vybereme možnost "Run GUI".
    
  ![image](https://github.com/lei1738/kry/assets/138430747/403ee99d-9427-4c24-8e16-c7a52534e4ee)
</details>


## Použití
<img width="902" alt="GUI" src="https://github.com/lei1738/kry/assets/138430747/9d5bdac3-7e77-49b0-80e3-8fe3426f1461">

  1. Sekce 1 má za cíl umožnit načtení souboru pro analýzu (Obrázek 3.5). Tato
  část obsahuje tlačítko Load Traffic a textové pole, které není editovatelné. Po
  stisknutí tlačítka se zobrazí dialogové okno, které umožňuje vyhledání a výběr
  souboru s formátem .pcap k načtení. Po úspěšném načtení se název souboru
  zobrazí v textovém poli pro snadnější identifikaci.
  2. Sekce 2 má za úkol zachytit provoz na zvoleném rozhraní po zvolenou dobu. V
  rozbalovacím seznamu si může uživatel vybrat síťové rozhraní na jeho zařízení
  a níže, pomocí posuvníku, si zvolit čas zachytávání. Tyto volby poté potvrdí
  tlačítkem Record Traffic.
  3. Sekce 3 obsahuje pouze tlačítko Analyze, které má na starost spuštění analýzy. Pokud nebyl nahrán soubor ani zachycen provoz, tak je toto tlačítko
  zamknuté. Poté se odemkne a změní své jméno dle volby uživatele (ať už nahrát soubor či zachytit provoz). V akci tlačítka Analyze probíhá i převedení
  souboru .pcap na .csv, zahashování obsahu souboru na čísla a následné předání
  neuronové síti k analýze provozu.
  4. Sekce 4 slouží k výpisu výsledků analýzy. Zahrnuje to procentuální část zašifrovaných paketů oproti celku, počet zašifrovaných paketů, použité protokoly,
  velikost jednotlivých paketů, zdrojové a cílové adresy a jejich početní výskyty.
  5. V sekci 5 se nachází pouze volba vzhledu okna. Na výběr je systémový mód,
  světlý mód a tmavý mód. Dále je k dispozici škálování uživatelského rozhraní, a to od 80 % do 120 %.
  6. Sekce 6 obsahuje pouze popis aplikace.

  - Je možné otestovat funkčnosti projektu na přiložených souborech ve složce pcap. Konkrétně jde o soubory: gmail_encrypted_traffic.pcap (pouze šifrovaná komunikace), test.pcap (smížená komunikace), test1.pcap (smížená komunikace), test2.pcap (smížená komunikace).

