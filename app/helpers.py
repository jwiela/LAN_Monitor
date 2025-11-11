"""
Funkcje pomocnicze wykorzystywane w całej aplikacji
"""


def format_bytes(bytes_value):
    """
    Formatuje bajty do odpowiedniej jednostki (1000-based, SI)
    
    Args:
        bytes_value: Wartość w bajtach
        
    Returns:
        str: Sformatowana wartość z jednostką (B, KB, MB, GB)
    """
    if bytes_value < 1000:
        return f"{bytes_value:.2f} B"
    elif bytes_value < 1000 * 1000:
        return f"{bytes_value / 1000:.2f} KB"
    elif bytes_value < 1000 * 1000 * 1000:
        return f"{bytes_value / 1000 / 1000:.2f} MB"
    else:
        return f"{bytes_value / 1000 / 1000 / 1000:.2f} GB"
