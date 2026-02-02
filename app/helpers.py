
#Funkcje pomocnicze wykorzystywane w całej aplikacji


"""Formatowanie bajtów do odpowiednich jednostek"""
def format_bytes(bytes_value):
    if bytes_value < 1000:
        return f"{bytes_value:.2f} B"
    elif bytes_value < 1000 * 1000:
        return f"{bytes_value / 1000:.2f} KB"
    elif bytes_value < 1000 * 1000 * 1000:
        return f"{bytes_value / 1000 / 1000:.2f} MB"
    else:
        return f"{bytes_value / 1000 / 1000 / 1000:.2f} GB"
