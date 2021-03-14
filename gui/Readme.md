# Zircolite mini-IHM

**La Mini-IHM permet de visualiser les détections effectuées par Zircolite**

:warning: Si elle peut être pratique pour un nombre limité de résultats, la mini-IHM ne se substitue pas à des outils comme Splunk. Si vous avez de nombreux résultats à traiter, utiliser le template d'export vers Splunk disponible dans le répertoire template.

![](../pics/gui.jpg)

## Auteur

**Wagga / Baptiste**

* [github/wagga40](https://github.com/wagga40)

## Prérequis 

### Données

La mini-IHM s'appuie sur le fichier `data.js` à mettre dans le même répertoire que l'IHM. Le fichier `data.js` doit être généré à partir du mécanisme de templating de Zircolite : 

```shell
python3 zircolite.py \
			--evtx ../Samples/EVTX-ATTACK-SAMPLES/ \
			--ruleset rules/rules_medium_sysmon_performance_v3.json \ 
			--template templates/exportForZircoGui.tmpl \ 
			--templateOutput data.js
mv data.js gui/

```

## Usage

Il suffit ensuite de placer le fichier `data.js` dans le même répertoire que la mini-IHM. Un fichier de démonstration est déjà présent et correspondant à l'utilisation de Zircolite sur le dépot suivant : [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).