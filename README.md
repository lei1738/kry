# Project: Encrypted Traffic Analysis

## Obsah:
  1. Popis
  2. Instalace
  3. Použití

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
  - Z GitHubu/místa odevzdání projektu na školních stránkách
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
    Krok 4: Nainstalovat Pycharm
  </summary>
    - Stáhnout Pycharm: https://www.jetbrains.com/pycharm/
</details>
<details>
  <summary>
    Krok 4: Nastavení statické kryptografické soli
  </summary>
</details>
<details>
  <summary>
    Krok 5: Spustit GUI.py
    - 
  </summary>
</details>

## Použití
