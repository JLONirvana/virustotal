import hashlib
from virus_total_apis import PublicApi
import tkinter as tk
from tkinter import filedialog
import requests

API_KEY = ""

api = PublicApi(API_KEY)


def file_analysis():
    # crea una ventana vacía y luego ocultarla
    ventana = tk.Tk()
    ventana.withdraw()
    archivo = filedialog.askopenfilename()

    with open(archivo, "rb") as file:
        file_hash = hashlib.md5(file.read()).hexdigest()
    response = api.get_file_report(file_hash)

    # el codigo 200 significa que la respuesta fue exitosa
    if response["response_code"] == 200:
        # para validar si en caso de que el analisis del archivo resulte malicioso
        if response["results"]["positives"] > 0:
            print("**********************************************")
            print("¡¡¡¡El archivo es malicioso!!!!")
            print("contactar al equipo de Seguridad Tecnológica")
            print("para su accion pertienete, o elimine el archivo")
            print("**********************************************")
        # si en caso no hay un analisis malicioso
        else:
            print("**********************************************")
            print("¡¡¡¡El archivo es seguro!!!!")
            print("**********************************************")
    else:
        "no se ha podido obtener el analisis del archivo"


def url_analysis():
    # api de la url
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    # solicitando la url
    url = input("Ingrese la url a analizar :")

    # definiendo los parámetros de peticion
    parametros = {"apikey": API_KEY, "resource": url}
    # enviando la peticion con le metodo POST
    response = requests.get(api_url, params=parametros)

    # imprimiendo el resultado de la peticion
    # print(response.json())
    if response.json()["response_code"] == 1:
        if response.json()["positives"] > 0:
            print("**********************************************")
            print("¡¡¡¡ la url es maliciosa !!!!")
            print("no habrir el link")
            print("contactar al equipo de Seguridad Tecnológica")
            print("para su accion pertienete")
            print("**********************************************")
        else:
            print("**********************************************")
            print("¡¡¡¡ La url es segura !!!!")
            print("**********************************************")
    else:
        print("no se ha podido obtener el analisis de la url")


if __name__ == "__main__":

    opcion = 0
    while opcion != 5:
        print("  ")
        print("Menu de opciones")
        print("------------------")
        print("1. Analizar un archivo")
        print("2. Analizar un URL, enlace o un link")
        print("5. Salir")
        opcion = int(input("Ingrese una opcion :"))
        print("  ")
        match opcion:
            case 1:
                file_analysis()
            case 2:
                url_analysis()
            case 5:
                print("Gracias por utlizar")
            case _:
                print("opcion inválida, vuele a ingresar")