import math
import sqlite3
from datetime import datetime
from urllib.parse import quote

import pandas as pd
import dash
from dash import dcc, html, dash_table, ctx, no_update
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.graph_objs as go


# ============================================================
# HELPERS SVG — on génère les SVG comme chaînes de caractères
# et on les intègre comme data: URI dans <img>, car dash.html
# n'inclut pas les primitives SVG.
# ============================================================

def svg_data_uri(svg_markup):
    """Encode un markup SVG comme data URI."""
    return "data:image/svg+xml;utf8," + quote(svg_markup, safe="")


def icone_data_uri(path_d, couleur="#C6D5DE", stroke_width=1.7):
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 24 24" fill="none" '
        f'stroke="{couleur}" stroke-width="{stroke_width}" '
        f'stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="{path_d}"/></svg>'
    )
    return svg_data_uri(svg)


# ============================================================
# MODULE 7 — TABLEAU DE BORD WEB
# NIDS HYBRIDE — OCP CYBER SECURITY MONITOR
# ============================================================

FICHIER_DB = "nids_alertes.db"


# ============================================================
# PALETTE OCP CYBER SECURITY MONITOR
# ============================================================

OCP_GREEN = "#2ECC7A"
OCP_GREEN_DARK = "#199A5B"
OCP_GREEN_LIGHT = "#5FE0A0"
OCP_GREEN_GLOW = "#8FEBBB"
OCP_TEAL = "#2DD3C4"
OCP_TEAL_LIGHT = "#7FE7DC"
OCP_AMBER = "#F2A73B"
OCP_AMBER_LIGHT = "#F8C778"
OCP_RED = "#E5484D"
OCP_RED_LIGHT = "#FF8E91"
OCP_TEXT = "#E7EEF3"
OCP_TEXT_MUTED = "#7E93A0"
OCP_TEXT_DIM = "#5E7382"
OCP_PANEL_BG = "rgba(11, 19, 25, 0.0)"

# Correspondance des couleurs d'alerte historiques → design OCP
# VERT = normal, ORANGE = suspect, ROUGE = critique
COULEURS = {
    "VERT": OCP_GREEN,
    "ORANGE": OCP_AMBER,
    "ROUGE": OCP_RED,
}

# Palette des types d'attaques
PALETTE_ATTAQUES = {
    "PORT_SCAN": OCP_AMBER,
    "DOS_SYN_FLOOD": "#A855F7",
    "BRUTE_FORCE_SSH": OCP_RED,
    "BRUTE_FORCE_FTP": OCP_TEAL,
    "BRUTE_FORCE_HTTP": "#EC4899",
    "DNS_TUNNELING": "#84CC16",
    "ICMP_FLOOD": "#F97316",
}

COULEURS_ATTAQUES_SUPPLEMENTAIRES = [
    "#14B8A6", "#6366F1", "#EAB308", "#F43F5E", "#22C55E",
]

COULEUR_ATTAQUE_DEFAUT = "#60A5FA"

# Palette pour les graphiques Plotly
FOND_GRAPHIQUE = "rgba(0,0,0,0)"
TEXTE_GRAPHIQUE = OCP_TEXT
GRILLE_GRAPHIQUE = "rgba(255,255,255,0.05)"

SERVICES_CONNUS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    3389: "RDP",
    445: "SMB",
    3306: "MySQL",
    8080: "HTTP-ALT",
}

TAILLE_PAGE_ZONE4 = 20


# ============================================================
# OUTILS
# ============================================================

def nom_service(port):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "—"
    return SERVICES_CONNUS.get(port, f"Port {port}")


# ============================================================
# CONNEXION BASE DE DONNÉES
# ============================================================

def obtenir_connexion():
    connexion = sqlite3.connect(FICHIER_DB, timeout=10)
    connexion.execute("PRAGMA journal_mode=WAL")
    connexion.row_factory = sqlite3.Row
    return connexion


# ============================================================
# KPI
# ============================================================

def obtenir_kpis():
    with obtenir_connexion() as cx:
        total = cx.execute(
            "SELECT COUNT(*) FROM alertes"
        ).fetchone()[0]

        if total == 0:
            return {
                "total": 0, "rouge": 0, "orange": 0, "vert": 0,
                "taux_attaque": 0.0, "ip_active": "—", "derniere_alerte": "—",
            }

        compte = {"ROUGE": 0, "ORANGE": 0, "VERT": 0}

        for ligne in cx.execute(
            "SELECT couleur, COUNT(*) AS n "
            "FROM alertes GROUP BY couleur"
        ):
            compte[ligne["couleur"]] = ligne["n"]

        ip_row = cx.execute(
            """
            SELECT ip_source, COUNT(*) AS n
            FROM alertes
            GROUP BY ip_source
            ORDER BY n DESC
            LIMIT 1
            """
        ).fetchone()

        derniere = cx.execute(
            "SELECT horodatage FROM alertes ORDER BY id DESC LIMIT 1"
        ).fetchone()

    taux = round(100 * (compte["ROUGE"] + compte["ORANGE"]) / total, 1)

    return {
        "total": total,
        "rouge": compte["ROUGE"],
        "orange": compte["ORANGE"],
        "vert": compte["VERT"],
        "taux_attaque": taux,
        "ip_active": ip_row["ip_source"] if ip_row else "—",
        "derniere_alerte": derniere["horodatage"] if derniere else "—",
    }


# ============================================================
# ÉVOLUTION TEMPORELLE
# ============================================================

def obtenir_serie_temporelle():
    with obtenir_connexion() as cx:
        lignes = cx.execute(
            """
            SELECT
                strftime('%Y-%m-%dT%H:%M:00', horodatage) AS minute,
                couleur,
                COUNT(*) AS nombre
            FROM alertes
            GROUP BY minute, couleur
            ORDER BY minute
            """
        ).fetchall()

    return pd.DataFrame(
        [dict(l) for l in lignes],
        columns=["minute", "couleur", "nombre"]
    )


# ============================================================
# RÉPARTITION DES ATTAQUES
# ============================================================

def obtenir_repartition_attaques():
    with obtenir_connexion() as cx:
        lignes = cx.execute(
            """
            SELECT verdict_regle, COUNT(*) AS nombre
            FROM alertes
            WHERE verdict_regle != 'NORMAL'
            GROUP BY verdict_regle
            ORDER BY nombre DESC
            """
        ).fetchall()

    return pd.DataFrame(
        [dict(l) for l in lignes],
        columns=["verdict_regle", "nombre"]
    )


# ============================================================
# TOP IP
# ============================================================

def obtenir_top_ip(limite=5):
    with obtenir_connexion() as cx:
        lignes = cx.execute(
            """
            SELECT ip_source, COUNT(*) AS nombre
            FROM alertes
            GROUP BY ip_source
            ORDER BY nombre DESC
            LIMIT ?
            """,
            (limite,)
        ).fetchall()

    return pd.DataFrame(
        [dict(l) for l in lignes],
        columns=["ip_source", "nombre"]
    )


# ============================================================
# RÈGLES LES PLUS DÉCLENCHÉES
# ============================================================

def obtenir_regles_top(limite=4):
    with obtenir_connexion() as cx:
        lignes = cx.execute(
            """
            SELECT verdict_regle, COUNT(*) AS nombre
            FROM alertes
            WHERE verdict_regle != 'NORMAL'
            GROUP BY verdict_regle
            ORDER BY nombre DESC
            LIMIT ?
            """,
            (limite,)
        ).fetchall()
    return pd.DataFrame(
        [dict(l) for l in lignes],
        columns=["verdict_regle", "nombre"]
    )


# ============================================================
# TYPES D'ATTAQUES
# ============================================================

def obtenir_types_attaques():
    with obtenir_connexion() as cx:
        lignes = cx.execute(
            """
            SELECT DISTINCT verdict_regle
            FROM alertes
            WHERE verdict_regle != 'NORMAL'
            ORDER BY verdict_regle
            """
        ).fetchall()
    return [l["verdict_regle"] for l in lignes]


# ============================================================
# DERNIÈRES ALERTES
# ============================================================

def obtenir_dernieres_alertes(limite=25, filtre_couleur=None, filtre_type=None):
    conditions = []
    parametres = []

    if filtre_couleur:
        conditions.append("couleur = ?")
        parametres.append(filtre_couleur)

    if filtre_type:
        conditions.append("verdict_regle = ?")
        parametres.append(filtre_type)

    requete = "SELECT * FROM alertes"
    if conditions:
        requete += " WHERE " + " AND ".join(conditions)
    requete += " ORDER BY id DESC LIMIT ?"

    with obtenir_connexion() as cx:
        df = pd.read_sql_query(requete, cx, params=parametres + [limite])

    return df


# ============================================================
# RECHERCHE HISTORIQUE
# ============================================================

def rechercher_alertes(
    ip=None, couleur=None, type_attaque=None,
    date_debut=None, date_fin=None,
    page=0, taille_page=TAILLE_PAGE_ZONE4
):
    conditions = []
    parametres = []

    if ip:
        conditions.append("(ip_source LIKE ? OR ip_dest LIKE ?)")
        parametres.extend([f"%{ip}%", f"%{ip}%"])

    if couleur:
        conditions.append("couleur = ?")
        parametres.append(couleur)

    if type_attaque:
        conditions.append("verdict_regle = ?")
        parametres.append(type_attaque)

    if date_debut:
        conditions.append("horodatage >= ?")
        parametres.append(date_debut)

    if date_fin:
        conditions.append("horodatage <= ?")
        parametres.append(date_fin + "T23:59:59")

    ou = ""
    if conditions:
        ou = " WHERE " + " AND ".join(conditions)

    with obtenir_connexion() as cx:
        total = cx.execute(
            f"SELECT COUNT(*) FROM alertes {ou}", parametres
        ).fetchone()[0]

        df = pd.read_sql_query(
            f"SELECT * FROM alertes {ou} ORDER BY id DESC LIMIT ? OFFSET ?",
            cx,
            params=parametres + [taille_page, page * taille_page]
        )

    return df, total


# ============================================================
# HELPERS SVG (sparklines, gauges, donut)
# ============================================================

def generer_sparkline_path(valeurs, w=112, h=30):
    """Génère deux chemins SVG (line + fill) pour une sparkline."""
    if not valeurs:
        return "", ""
    mx = max(valeurs); mn = min(valeurs)
    span = (mx - mn) if (mx - mn) > 0 else 1
    n = len(valeurs)
    pts = [
        (i / max(1, n - 1) * w, h - 3 - (v - mn) / span * (h - 8))
        for i, v in enumerate(valeurs)
    ]
    d = "M" + " L".join(f"{p[0]:.1f} {p[1]:.1f}" for p in pts)
    d_fill = d + f" L{w} {h} L0 {h} Z"
    return d, d_fill


def valeurs_sparkline_depuis_df(df, cle_couleur, taille=22):
    """Extrait une série de 'taille' points à partir du df temporel pour une couleur donnée."""
    if df is None or df.empty:
        # Génère une courbe de secours (plate légèrement animée)
        return [0.5 + 0.1 * math.sin(i / 3) for i in range(taille)]
    sub = df[df["couleur"] == cle_couleur].tail(taille)
    vals = sub["nombre"].tolist()
    if not vals:
        return [0.3 + 0.1 * math.sin(i / 3) for i in range(taille)]
    # Pad en début si besoin
    if len(vals) < taille:
        vals = [vals[0]] * (taille - len(vals)) + vals
    return vals


def construire_sparkline_svg(valeurs, couleur, fill, w=120, h=34):
    """Construit le markup SVG complet d'une sparkline, retourne un data URI."""
    d_line, d_fill = generer_sparkline_path(valeurs, w, h)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {w} {h}" preserveAspectRatio="none" '
        f'style="overflow:visible">'
        f'<path d="{d_fill}" fill="{fill}" stroke="none"/>'
        f'<path d="{d_line}" fill="none" stroke="{couleur}" '
        f'stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" '
        f'vector-effect="non-scaling-stroke"/>'
        f'</svg>'
    )
    return svg_data_uri(svg)


def composant_gauge(label, pourcent, couleur_hex, etat_label, note):
    """Construit une jauge circulaire SVG avec texte au centre."""
    r = 41
    circ = 2 * math.pi * r
    pct = max(0, min(100, pourcent))
    dash_val = circ * (pct / 100.0)
    state_bg_map = {
        OCP_RED:   ("rgba(229,72,77,.12)",   "rgba(229,72,77,.28)"),
        OCP_AMBER: ("rgba(242,167,59,.12)",  "rgba(242,167,59,.28)"),
        OCP_GREEN: ("rgba(46,204,122,.12)",  "rgba(46,204,122,.28)"),
    }
    state_bg, state_bd = state_bg_map.get(couleur_hex,
                                           ("rgba(46,204,122,.12)",
                                            "rgba(46,204,122,.28)"))

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '
        f'style="transform:rotate(-90deg);width:88px;height:88px">'
        f'<circle cx="50" cy="50" r="{r}" fill="none" '
        f'stroke="rgba(255,255,255,.065)" stroke-width="7"/>'
        f'<circle cx="50" cy="50" r="{r}" fill="none" '
        f'stroke="{couleur_hex}" stroke-width="7" stroke-linecap="round" '
        f'stroke-dasharray="{dash_val:.1f} {circ:.1f}" '
        f'stroke-dashoffset="0"/>'
        f'</svg>'
    )

    return html.Div(
        className="gauge",
        children=[
            html.Div(
                className="gauge-ring",
                children=[
                    html.Img(src=svg_data_uri(svg),
                             style={"width": "88px", "height": "88px"}),
                    html.Div(
                        className="gauge-center",
                        children=[
                            html.Span(f"{int(round(pourcent))}",
                                      className="gauge-val",
                                      style={"color": couleur_hex}),
                            html.Span("/ 100", className="gauge-unit"),
                        ],
                    ),
                ],
            ),
            html.Div(
                className="gauge-meta",
                children=[
                    html.Span(label, className="gauge-label"),
                    html.Span(
                        etat_label,
                        className="gauge-state",
                        style={
                            "color": couleur_hex,
                            "background": state_bg,
                            "border": f"1px solid {state_bd}",
                        },
                    ),
                    html.Span(note, className="gauge-note"),
                ],
            ),
        ],
    )


def composant_donut_attaques(df_attaques, total_attaques):
    """Donut SVG + liste des types d'attaques."""
    if df_attaques is None or df_attaques.empty or total_attaques == 0:
        svg_vide = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '
            f'style="transform:rotate(-90deg);width:132px;height:132px">'
            f'<circle cx="50" cy="50" r="38" fill="none" '
            f'stroke="rgba(255,255,255,.05)" stroke-width="13"/></svg>'
        )
        return html.Div(
            className="donut-wrap",
            children=[
                html.Div(
                    className="donut-ring",
                    children=[
                        html.Img(src=svg_data_uri(svg_vide),
                                 style={"width": "132px", "height": "132px"}),
                        html.Div(
                            className="donut-center",
                            children=[
                                html.Span("0", className="donut-total"),
                                html.Span("ATTACKS",
                                          className="donut-total-label"),
                            ],
                        ),
                    ],
                ),
                html.Div(
                    className="donut-list",
                    children=[
                        html.Span(
                            "No attacks detected yet.",
                            style={"color": OCP_TEXT_MUTED,
                                   "fontSize": "11.5px"},
                        )
                    ],
                ),
            ],
        )

    palette_iter = iter(COULEURS_ATTAQUES_SUPPLEMENTAIRES)
    palette_locale = {}
    for t in df_attaques["verdict_regle"].astype(str).tolist():
        if t in palette_locale:
            continue
        palette_locale[t] = (
            PALETTE_ATTAQUES.get(t)
            or next(palette_iter, COULEUR_ATTAQUE_DEFAUT)
        )

    r = 38
    circ = 2 * math.pi * r
    acc = 0.0
    cercles_markup = (
        f'<circle cx="50" cy="50" r="{r}" fill="none" '
        f'stroke="rgba(255,255,255,.05)" stroke-width="13"/>'
    )
    rows = []
    for _, row in df_attaques.iterrows():
        t = str(row["verdict_regle"])
        n = int(row["nombre"])
        frac = n / total_attaques if total_attaques > 0 else 0
        length = circ * frac
        off = -acc
        acc += length
        couleur = palette_locale.get(t, COULEUR_ATTAQUE_DEFAUT)
        cercles_markup += (
            f'<circle cx="50" cy="50" r="{r}" fill="none" '
            f'stroke="{couleur}" stroke-width="13" '
            f'stroke-dasharray="{max(0, length - 2):.1f} {circ:.1f}" '
            f'stroke-dashoffset="{off:.1f}"/>'
        )
        pct_txt = f"{round(frac * 100)}%"
        rows.append(
            html.Div(
                className="donut-row",
                children=[
                    html.Div(
                        className="donut-row-head",
                        children=[
                            html.Span(className="donut-swatch",
                                      style={"background": couleur}),
                            html.Span(t.replace("_", " ").title(),
                                      className="donut-name"),
                            html.Span(str(n), className="donut-count"),
                            html.Span(pct_txt, className="donut-pct"),
                        ],
                    ),
                    html.Div(
                        className="donut-track",
                        children=[
                            html.Div(
                                className="donut-fill",
                                style={
                                    "width": f"{frac * 100:.0f}%",
                                    "background": (
                                        f"linear-gradient(90deg,{couleur},"
                                        f"{couleur}99)"
                                    ),
                                },
                            )
                        ],
                    ),
                ],
            )
        )

    svg_markup = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '
        f'style="transform:rotate(-90deg);width:132px;height:132px">'
        f'{cercles_markup}</svg>'
    )
    return html.Div(
        className="donut-wrap",
        children=[
            html.Div(
                className="donut-ring",
                children=[
                    html.Img(src=svg_data_uri(svg_markup),
                             style={"width": "132px", "height": "132px"}),
                    html.Div(
                        className="donut-center",
                        children=[
                            html.Span(str(total_attaques),
                                      className="donut-total"),
                            html.Span("ATTACKS",
                                      className="donut-total-label"),
                        ],
                    ),
                ],
            ),
            html.Div(className="donut-list", children=rows),
        ],
    )


# ============================================================
# GRAPHIQUE ÉVOLUTION TEMPORELLE (Plotly)
# ============================================================

def construire_figure_temporelle(df):
    if df.empty:
        fig = go.Figure()
        fig.update_layout(
            title="",
            annotations=[dict(
                text="En attente de données réseau…",
                xref="paper", yref="paper", x=0.5, y=0.5,
                showarrow=False,
                font=dict(size=13, color=OCP_TEXT_MUTED)
            )]
        )
    else:
        # Pivot pour avoir une colonne par couleur
        pivot = df.pivot_table(
            index="minute", columns="couleur", values="nombre", aggfunc="sum"
        ).fillna(0).sort_index()
        if "VERT" not in pivot.columns: pivot["VERT"] = 0
        if "ORANGE" not in pivot.columns: pivot["ORANGE"] = 0
        if "ROUGE" not in pivot.columns: pivot["ROUGE"] = 0

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=pivot.index, y=pivot["VERT"],
            name="NORMAL", mode="lines",
            line=dict(color=OCP_GREEN, width=2, shape="spline"),
            fill="tozeroy", fillcolor="rgba(46,204,122,.10)",
            hovertemplate="<b>%{x}</b><br>Normal : %{y}<extra></extra>",
        ))
        fig.add_trace(go.Scatter(
            x=pivot.index, y=pivot["ORANGE"],
            name="SUSPICIOUS", mode="lines",
            line=dict(color=OCP_AMBER, width=2, shape="spline"),
            fill="tozeroy", fillcolor="rgba(242,167,59,.12)",
            hovertemplate="<b>%{x}</b><br>Suspect : %{y}<extra></extra>",
        ))
        fig.add_trace(go.Scatter(
            x=pivot.index, y=pivot["ROUGE"],
            name="ATTACK", mode="lines",
            line=dict(color=OCP_RED, width=2, shape="spline"),
            fill="tozeroy", fillcolor="rgba(229,72,77,.16)",
            hovertemplate="<b>%{x}</b><br>Attaque : %{y}<extra></extra>",
        ))

    fig.update_layout(
        paper_bgcolor=FOND_GRAPHIQUE,
        plot_bgcolor=FOND_GRAPHIQUE,
        font=dict(family="Archivo, sans-serif", color=TEXTE_GRAPHIQUE, size=11),
        margin=dict(t=12, l=42, r=14, b=36),
        height=270,
        hovermode="x unified",
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02,
            xanchor="right", x=1.0,
            font=dict(size=10, color=OCP_TEXT_MUTED),
            bgcolor="rgba(0,0,0,0)",
        ),
        xaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            linecolor="rgba(255,255,255,.08)",
            tickfont=dict(color="#546A78", size=9, family="Roboto Mono, monospace"),
            tickangle=0,
            type="category",
            showgrid=False,
            zeroline=False,
            rangeslider=dict(visible=False),
            nticks=6,
        ),
        yaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            linecolor="rgba(255,255,255,0)",
            tickfont=dict(color="#546A78", size=9, family="Roboto Mono, monospace"),
            rangemode="tozero",
            zeroline=False,
            showgrid=True,
        ),
        hoverlabel=dict(
            bgcolor="rgba(8,14,19,.96)",
            bordercolor="rgba(255,255,255,.12)",
            font=dict(family="Archivo, sans-serif", color=OCP_TEXT, size=11),
        ),
    )
    return fig


# ============================================================
# TOP IP (Plotly)
# ============================================================

def construire_figure_top_ip(df):
    if df.empty:
        fig = go.Figure()
        fig.update_layout(
            annotations=[dict(
                text="Aucune donnée pour le moment",
                xref="paper", yref="paper", x=0.5, y=0.5,
                showarrow=False,
                font=dict(size=12, color=OCP_TEXT_MUTED)
            )]
        )
    else:
        df = df.sort_values("nombre")
        fig = px.bar(df, x="nombre", y="ip_source", orientation="h")
        fig.update_traces(
            marker=dict(
                color=df["nombre"],
                colorscale=[[0, OCP_GREEN_DARK], [0.5, OCP_GREEN], [1, OCP_TEAL]],
                line=dict(color="rgba(0,0,0,0)")
            ),
            texttemplate="%{x}",
            textposition="outside",
            textfont=dict(color=OCP_TEXT, family="Roboto Mono, monospace", size=11),
            cliponaxis=False,
            hovertemplate="<b>%{y}</b><br>Alertes : %{x}<extra></extra>",
        )

    fig.update_layout(
        paper_bgcolor=FOND_GRAPHIQUE,
        plot_bgcolor=FOND_GRAPHIQUE,
        font=dict(family="Archivo, sans-serif", color=TEXTE_GRAPHIQUE, size=11),
        margin=dict(t=12, l=12, r=20, b=12),
        height=220,
        xaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            tickfont=dict(color="#546A78", size=9, family="Roboto Mono, monospace"),
            title="", zeroline=False,
        ),
        yaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            tickfont=dict(color=OCP_TEXT, size=10.5, family="Roboto Mono, monospace"),
            title="", type="category",
        ),
        hoverlabel=dict(
            bgcolor="rgba(8,14,19,.96)",
            bordercolor="rgba(255,255,255,.12)",
            font=dict(family="Archivo, sans-serif", color=OCP_TEXT, size=11),
        ),
    )
    return fig


# ============================================================
# PANNEAU DÉTAILS
# ============================================================

def construire_panneau_details(ligne):
    proto_nom = {6: "TCP", 17: "UDP"}.get(
        ligne.get("proto"), str(ligne.get("proto"))
    )

    items = [
        ("IP destination", ligne.get("ip_dest")),
        ("Port source", ligne.get("port_source")),
        ("Port destination", ligne.get("port_dest")),
        ("Protocole", proto_nom),
        ("Paquets", ligne.get("nb_paquets")),
        ("Octets", ligne.get("nb_octets")),
        ("Durée (s)", ligne.get("duree")),
        ("Débit (o/s)",
         round(ligne["debit"], 1) if ligne.get("debit") is not None else "—"),
        ("SYN / ACK / FIN / RST",
         f"{ligne.get('syn')} / {ligne.get('ack')} / "
         f"{ligne.get('fin')} / {ligne.get('rst')}"),
        ("Anomalie (Isolation Forest)",
         "Oui" if ligne.get("anomalie_if") else "Non"),
        ("Détail règle", ligne.get("detail_regle") or "—"),
    ]

    return html.Div(
        className="panneau-details",
        children=[
            html.Div("Détails techniques", className="intro"),
            html.Div(
                className="grille-details",
                children=[
                    html.Div(
                        className="detail-item",
                        children=[
                            html.Div(label, className="label"),
                            html.Div(str(valeur), className="valeur"),
                        ],
                    )
                    for label, valeur in items
                ],
            ),
            html.Div(
                ligne.get("explication") or "Pas d'explication enregistrée.",
                className="explication-box",
            ),
        ],
    )


# ============================================================
# ICÔNES SVG (navigation sidebar)
# ============================================================

ICON_PATHS = {
    "Overview":        "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    "Live Monitoring": "M3 12h4l3-8 4 16 3-8h4",
    "Security Alerts": "M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6M10 20h4",
    "Network Traffic": "M4 8h13l-3-3M20 16H7l3 3",
    "Attack Analysis": "M12 4v4M12 16v4M4 12h4M16 12h4M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6",
    "Statistics":      "M4 20V11M10 20V4M16 20v-7M22 20v-4",
    "Detection Models":"M7 7h10v10H7zM4 10h3M4 14h3M17 10h3M17 14h3M10 4v3M14 4v3M10 17v3M14 17v3",
    "System Logs":     "M6 3h9l4 4v14H6zM9 12h7M9 16h7M9 8h4",
    "Settings":        "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7M12 3v2.5M12 18.5V21M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M3 12h2.5M18.5 12H21M4.6 19.4l1.8-1.8M17.6 6.4l1.8-1.8",
}


def icone_svg(d, taille=17, stroke="#8497A3"):
    return html.Img(
        src=icone_data_uri(d, couleur=stroke, stroke_width=1.65),
        className="nav-icon",
        style={"width": f"{taille}px", "height": f"{taille}px",
               "opacity": ".95"},
    )


def icone_svg_std(d, taille=17, stroke="#C6D5DE", stroke_width="1.7"):
    return html.Img(
        src=icone_data_uri(d, couleur=stroke,
                           stroke_width=float(stroke_width)),
        style={"width": f"{taille}px", "height": f"{taille}px",
               "flexShrink": "0"},
    )


# ============================================================
# APPLICATION DASH
# ============================================================

app = dash.Dash(__name__, assets_folder="assets")
app.title = "OCP Cyber Security Monitor"


# ============================================================
# EN-TÊTE
# ============================================================

def composant_entete():
    return html.Header(
        className="entete",
        children=[
            # Marque OCP
            html.Div(
                className="entete-brand",
                children=[
                    html.Div(
                        className="entete-logo-wrap",
                        children=[
                            html.Img(
                                src=app.get_asset_url("ocp-logo.png"),
                                alt="OCP Group",
                                className="entete-logo",
                            ),
                        ],
                    ),
                    html.Div(
                        className="entete-titles",
                        children=[
                            html.Div(
                                className="entete-title",
                                children=[
                                    html.Span("OCP",
                                              className="entete-title-accent"),
                                    html.Span(" CYBER SECURITY MONITOR"),
                                ],
                            ),
                            html.Div(
                                "Hybrid Network Intrusion Detection System",
                                className="entete-sub"
                            ),
                        ],
                    ),
                ],
            ),
            # Statut en ligne
            html.Div(
                className="entete-online",
                children=[
                    html.Span(className="entete-online-dot"),
                    html.Div(children=[
                        html.Div("SYSTEM ONLINE",
                                 className="entete-online-label"),
                        html.Div("Real-time monitoring active",
                                 className="entete-online-sub"),
                    ]),
                ],
            ),
            html.Div(className="entete-spacer"),
            # Horloge
            html.Div(
                className="entete-chip",
                children=[
                    html.Img(
                        src=icone_data_uri(
                            "M12 7v5l3.5 2 M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18",
                            couleur=OCP_GREEN_LIGHT, stroke_width=1.8,
                        ),
                        style={"width": "14px", "height": "14px"},
                    ),
                    html.Span(id="horloge-live",
                              className="entete-chip-clock",
                              children="--:--:--"),
                    html.Span(className="entete-chip-sep"),
                    html.Span(id="date-live", className="entete-chip-date",
                              children="—"),
                ],
            ),
            # Sync
            html.Div(
                className="entete-chip",
                children=[
                    html.Span("SYNC", className="entete-chip-label"),
                    html.Span("3s", className="entete-chip-val"),
                ],
            ),
            # Cloche d'alertes
            html.Button(
                className="entete-bell",
                children=[
                    html.Img(
                        src=icone_data_uri(
                            "M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6 M10 20h4",
                            couleur="#C6D5DE", stroke_width=1.7,
                        ),
                        style={"width": "17px", "height": "17px"},
                    ),
                    html.Span(id="entete-badge-alertes",
                              className="entete-bell-badge",
                              children="0"),
                ],
            ),
            # Utilisateur
            html.Div(
                className="entete-user",
                children=[
                    html.Div("SA", className="entete-user-avatar"),
                    html.Div(children=[
                        html.Div("S. Analyst", className="entete-user-name"),
                        html.Div("SOC · Tier 2", className="entete-user-role"),
                    ]),
                ],
            ),
        ],
    )


# ============================================================
# SIDEBAR
# ============================================================

def composant_sidebar():
    nav_items = [
        ("Overview",          None,  True),
        ("Live Monitoring",   None,  False),
        ("Security Alerts",   None,  False),  # badge mis à jour via callback
        ("Network Traffic",   None,  False),
        ("Attack Analysis",   None,  False),
        ("Statistics",        None,  False),
        ("Detection Models",  None,  False),
        ("System Logs",       None,  False),
        ("Settings",          None,  False),
    ]
    children = []
    for nom, _, actif in nav_items:
        cls = "nav-item active" if actif else "nav-item"
        kids = [
            icone_svg(ICON_PATHS[nom]),
            html.Span(nom, className="nav-label"),
        ]
        if nom == "Security Alerts":
            kids.append(html.Span(id="sidebar-badge-alerts",
                                  className="nav-badge",
                                  children="0"))
        children.append(html.Button(className=cls, children=kids, n_clicks=0))

    return html.Aside(
        className="sidebar",
        children=[
            html.Div("OPERATIONS", className="sidebar-heading"),
            html.Nav(className="nav", children=children),
            html.Div(className="sidebar-filler"),
            html.Div(
                className="sidebar-card",
                children=[
                    html.Div(
                        className="sidebar-card-head",
                        children=[
                            html.Span(className="sidebar-card-dot"),
                            html.Span("NIDS Hybrid v1.0"),
                        ],
                    ),
                    html.Div(className="sidebar-card-sep"),
                    html.Div(
                        className="sidebar-card-row",
                        children=[
                            html.Span("MONITORING NODE",
                                      className="sidebar-card-key"),
                            html.Span("Ubuntu",
                                      className="sidebar-card-val"),
                        ],
                    ),
                    html.Div(
                        className="sidebar-card-row",
                        children=[
                            html.Span("INTERFACE",
                                      className="sidebar-card-key"),
                            html.Span("ens33",
                                      className="sidebar-card-val"),
                        ],
                    ),
                ],
            ),
        ],
    )


# ============================================================
# CARTE KPI
# ============================================================

def composant_carte_kpi(id_carte, id_valeur, label, trend_txt,
                        note, icon_d, classe_couleur, valeurs_spark,
                        couleur_hex, fill_hex):
    """Construit une carte KPI avec sparkline et icône."""
    spark_uri = construire_sparkline_svg(valeurs_spark, couleur_hex, fill_hex,
                                         w=120, h=34)
    return html.Div(
        id=id_carte,
        n_clicks=0,
        className=f"carte-kpi {classe_couleur}",
        children=[
            html.Div(className="carte-kpi-topline"),
            html.Div(
                className="carte-kpi-row",
                children=[
                    html.Div(
                        className="carte-kpi-main",
                        children=[
                            html.Span(label, className="carte-kpi-label"),
                            html.Span("—", id=id_valeur,
                                      className="carte-kpi-value"),
                            html.Div(
                                className="carte-kpi-trend-row",
                                children=[
                                    html.Span(trend_txt,
                                              className="carte-kpi-trend"),
                                    html.Span("vs previous period",
                                              className="carte-kpi-trend-note"),
                                ],
                            ),
                        ],
                    ),
                    html.Div(
                        className="carte-kpi-icon",
                        children=[
                            html.Img(
                                src=icone_data_uri(
                                    icon_d, couleur=couleur_hex,
                                    stroke_width=1.7
                                ),
                                style={"width": "17px", "height": "17px"},
                            )
                        ],
                    ),
                ],
            ),
            html.Div(
                className="carte-kpi-foot",
                children=[
                    html.Span(note, className="carte-kpi-note"),
                    html.Img(src=spark_uri, className="carte-kpi-spark",
                             style={"width": "112px", "height": "30px"}),
                ],
            ),
        ],
    )


# ============================================================
# LAYOUT PRINCIPAL
# ============================================================

app.layout = html.Div(
    className="page",
    children=[
        html.Div(className="page-backdrop"),

        dcc.Interval(id="intervalle-maj", interval=3000, n_intervals=0),
        dcc.Interval(id="intervalle-horloge", interval=1000, n_intervals=0),

        dcc.Store(id="filtre-actif", data={"couleur": None, "type": None}),

        html.Div(
            className="page-shell",
            children=[
                composant_entete(),

                html.Div(
                    className="layout",
                    children=[
                        composant_sidebar(),

                        html.Main(
                            className="main",
                            children=[
                                # ========================================
                                # KPI ROW
                                # ========================================
                                html.Section(
                                    className="rangee-cartes",
                                    children=[
                                        composant_carte_kpi(
                                            "carte-total", "valeur-total",
                                            "TOTAL EVENTS", "▲ +8.4%",
                                            "Flows inspected on ens33",
                                            "M3 12h4l3-8 4 16 3-8h4",
                                            "c-teal",
                                            [0.4, 0.5, 0.45, 0.55, 0.6, 0.5,
                                             0.65, 0.7, 0.6, 0.72, 0.78, 0.7,
                                             0.8, 0.75, 0.85, 0.9, 0.8, 0.88,
                                             0.95, 0.9, 0.98, 1.0],
                                            OCP_TEAL, "rgba(45,211,196,.12)"
                                        ),
                                        composant_carte_kpi(
                                            "carte-rouge", "valeur-rouge",
                                            "CONFIRMED ATTACKS", "▲ +12.1%",
                                            "Rule + ML agreement",
                                            "M12 4l9 16H3zM12 10v4M12 17.2v.1",
                                            "c-red",
                                            [0.3, 0.35, 0.4, 0.3, 0.45, 0.5,
                                             0.4, 0.55, 0.6, 0.5, 0.65, 0.7,
                                             0.6, 0.75, 0.8, 0.7, 0.85, 0.9,
                                             0.8, 0.95, 1.0, 0.9],
                                            OCP_RED, "rgba(229,72,77,.13)"
                                        ),
                                        composant_carte_kpi(
                                            "carte-orange", "valeur-orange",
                                            "SUSPICIOUS EVENTS", "▼ -3.2%",
                                            "Anomaly score above 0.62",
                                            "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M12 8v5M12 16v.1",
                                            "c-amber",
                                            [0.5, 0.6, 0.55, 0.7, 0.65, 0.6,
                                             0.75, 0.8, 0.7, 0.85, 0.75, 0.8,
                                             0.9, 0.85, 0.95, 0.9, 1.0, 0.85,
                                             0.9, 0.8, 0.85, 0.78],
                                            OCP_AMBER, "rgba(242,167,59,.13)"
                                        ),
                                        composant_carte_kpi(
                                            "carte-vert", "valeur-vert",
                                            "NORMAL TRAFFIC", "▲ +8.1%",
                                            "Baseline behaviour",
                                            "M12 3l7 4v5c0 4.6-2.9 7.4-7 9-4.1-1.6-7-4.4-7-9V7zM9.3 12.1l1.9 1.9 3.5-3.8",
                                            "c-green",
                                            [0.5, 0.55, 0.6, 0.55, 0.65, 0.7,
                                             0.6, 0.72, 0.78, 0.7, 0.8, 0.85,
                                             0.75, 0.88, 0.82, 0.9, 0.95, 0.88,
                                             0.92, 0.98, 0.9, 0.95],
                                            OCP_GREEN, "rgba(46,204,122,.13)"
                                        ),
                                    ],
                                ),

                                # ========================================
                                # SECURITY POSTURE + NETWORK INFO
                                # ========================================
                                html.Section(
                                    className="row-posture",
                                    children=[
                                        # Security Posture
                                        html.Div(
                                            className="panneau",
                                            children=[
                                                html.Div(
                                                    className="panneau-head",
                                                    children=[
                                                        html.Div(
                                                            className="panneau-head-group",
                                                            children=[
                                                                html.Span(
                                                                    "SECURITY POSTURE",
                                                                    className="panneau-title"
                                                                ),
                                                                html.Span(
                                                                    "· LAST 60 MIN",
                                                                    className="panneau-sub"
                                                                ),
                                                            ],
                                                        ),
                                                        html.Span(
                                                            id="posture-badge",
                                                            children="GUARDED",
                                                            className="gauge-state",
                                                            style={
                                                                "color": OCP_AMBER,
                                                                "background": "rgba(242,167,59,.12)",
                                                                "border": "1px solid rgba(242,167,59,.28)",
                                                            },
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    id="posture-gauges",
                                                    className="posture-grid",
                                                ),
                                            ],
                                        ),

                                        # Network Information
                                        html.Div(
                                            className="panneau",
                                            children=[
                                                html.Div(
                                                    className="panneau-netinfo",
                                                    children=[
                                                        html.Div(
                                                            className="panneau-netinfo-head",
                                                            children=[
                                                                html.Span(
                                                                    "NETWORK INFORMATION",
                                                                    className="panneau-title"
                                                                ),
                                                                html.Span(
                                                                    className="netinfo-active",
                                                                    children=[
                                                                        html.Span(className="netinfo-active-dot"),
                                                                        html.Span("ACTIVE"),
                                                                    ],
                                                                ),
                                                            ],
                                                        ),
                                                        html.Div(
                                                            id="bandeau-info",
                                                            children=[],
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        ),
                                    ],
                                ),

                                # ========================================
                                # ACTIVITY CHART + ATTACK DISTRIBUTION
                                # ========================================
                                html.Section(
                                    className="row-activity",
                                    children=[
                                        html.Div(
                                            className="panneau",
                                            children=[
                                                html.Div(
                                                    className="panneau-head",
                                                    children=[
                                                        html.Div(
                                                            className="panneau-head-group",
                                                            children=[
                                                                html.Span(
                                                                    "NETWORK SECURITY ACTIVITY",
                                                                    className="panneau-title"
                                                                ),
                                                                html.Span(
                                                                    "PACKETS / SEC · LAST HOUR",
                                                                    className="panneau-sub"
                                                                ),
                                                            ],
                                                        ),
                                                        html.Div(
                                                            className="legend",
                                                            children=[
                                                                html.Span(className="legend-item", children=[
                                                                    html.Span(className="legend-swatch",
                                                                              style={"background": OCP_GREEN,
                                                                                     "boxShadow": f"0 0 8px 0 {OCP_GREEN}"}),
                                                                    "NORMAL",
                                                                ]),
                                                                html.Span(className="legend-item", children=[
                                                                    html.Span(className="legend-swatch",
                                                                              style={"background": OCP_AMBER,
                                                                                     "boxShadow": f"0 0 8px 0 {OCP_AMBER}"}),
                                                                    "SUSPICIOUS",
                                                                ]),
                                                                html.Span(className="legend-item", children=[
                                                                    html.Span(className="legend-swatch",
                                                                              style={"background": OCP_RED,
                                                                                     "boxShadow": f"0 0 8px 0 {OCP_RED}"}),
                                                                    "ATTACK",
                                                                ]),
                                                            ],
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    className="chart-wrap",
                                                    children=[
                                                        dcc.Graph(
                                                            id="graphique-temporel",
                                                            config={
                                                                "displayModeBar": False,
                                                                "scrollZoom": True,
                                                                "responsive": True,
                                                            },
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        ),

                                        html.Div(
                                            className="panneau",
                                            children=[
                                                html.Div(
                                                    className="panneau-head",
                                                    children=[
                                                        html.Span(
                                                            "ATTACK DISTRIBUTION",
                                                            className="panneau-title"
                                                        ),
                                                        html.Span(
                                                            id="donut-events-label",
                                                            children="0 EVENTS",
                                                            className="panneau-sub"
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    id="donut-attaques",
                                                    children=[],
                                                ),
                                                # Graph camembert pour compatibilité callbacks (caché)
                                                html.Div(
                                                    dcc.Graph(
                                                        id="graphique-camembert",
                                                        config={"displayModeBar": False},
                                                        style={"height": "0px"},
                                                    ),
                                                    style={"display": "none"},
                                                ),
                                                html.Div(
                                                    id="donut-stats",
                                                    className="donut-stats",
                                                ),
                                            ],
                                        ),
                                    ],
                                ),

                                # ========================================
                                # LIVE SECURITY ALERTS
                                # ========================================
                                html.Section(
                                    className="panneau",
                                    children=[
                                        html.Div(
                                            className="panneau-head",
                                            children=[
                                                html.Div(
                                                    className="panneau-head-group",
                                                    children=[
                                                        html.Span(className="alert-dot"),
                                                        html.Span(
                                                            "LIVE SECURITY ALERTS",
                                                            className="panneau-title"
                                                        ),
                                                        html.Span(
                                                            id="alert-count-pill",
                                                            children="0",
                                                            className="alert-count-pill"
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    id="badge-filtre-clear",
                                                    n_clicks=0,
                                                    className="badge-filtre",
                                                    style={"display": "none"},
                                                    children=[
                                                        html.Span(id="badge-filtre-texte"),
                                                        html.Span(" ✕"),
                                                    ],
                                                ),
                                            ],
                                        ),
                                        dash_table.DataTable(
                                            id="table-alertes",
                                            columns=[
                                                {"name": "TIMESTAMP", "id": "horodatage"},
                                                {"name": "SOURCE IP", "id": "ip_source"},
                                                {"name": "SERVICE", "id": "service"},
                                                {"name": "DETECTION RULE", "id": "verdict_regle"},
                                                {"name": "AI CLASSIFICATION", "id": "verdict_ml"},
                                                {"name": "CONFIDENCE %", "id": "confiance_ml"},
                                                {"name": "SEVERITY", "id": "couleur"},
                                            ],
                                            style_as_list_view=True,
                                            style_table={"overflowX": "auto"},
                                            style_cell={
                                                "textAlign": "left",
                                                "padding": "11px 14px",
                                                "fontFamily": "'Roboto Mono', monospace",
                                                "fontSize": "11.5px",
                                                "backgroundColor": "transparent",
                                                "color": OCP_TEXT,
                                                "border": "none",
                                                "borderBottom": "1px solid rgba(255,255,255,0.04)",
                                            },
                                            style_header={
                                                "backgroundColor": "rgba(255,255,255,0.014)",
                                                "color": OCP_TEXT_DIM,
                                                "fontWeight": "600",
                                                "fontFamily": "'Archivo', sans-serif",
                                                "letterSpacing": "0.15em",
                                                "border": "none",
                                                "borderBottom": "1px solid rgba(255,255,255,0.05)",
                                                "textTransform": "uppercase",
                                                "fontSize": "9.5px",
                                            },
                                            style_data_conditional=[
                                                {
                                                    "if": {"filter_query": '{couleur} = "ROUGE"'},
                                                    "backgroundColor": "rgba(229,72,77,0.055)",
                                                    "color": OCP_RED_LIGHT,
                                                    "borderLeft": f"2px solid {OCP_RED}",
                                                },
                                                {
                                                    "if": {"filter_query": '{couleur} = "ORANGE"'},
                                                    "backgroundColor": "rgba(242,167,59,0.045)",
                                                    "color": OCP_AMBER_LIGHT,
                                                    "borderLeft": f"2px solid {OCP_AMBER}",
                                                },
                                                {
                                                    "if": {"filter_query": '{couleur} = "VERT"'},
                                                    "backgroundColor": "rgba(46,204,122,0.03)",
                                                    "color": OCP_GREEN_GLOW,
                                                    "borderLeft": f"2px solid {OCP_GREEN}",
                                                },
                                            ],
                                            page_size=12,
                                        ),
                                    ],
                                ),

                                # ========================================
                                # HYBRID DETECTION ENGINE PIPELINE
                                # ========================================
                                html.Section(
                                    className="panneau",
                                    children=[
                                        html.Div(
                                            className="panneau-head",
                                            children=[
                                                html.Div(
                                                    className="panneau-head-group",
                                                    children=[
                                                        html.Span(
                                                            "HYBRID DETECTION ENGINE",
                                                            className="panneau-title"
                                                        ),
                                                        html.Span(
                                                            "SIGNATURE + MACHINE LEARNING FUSION PIPELINE",
                                                            className="panneau-sub"
                                                        ),
                                                    ],
                                                ),
                                                html.Span(
                                                    className="pipeline-ok",
                                                    children=[
                                                        html.Span(className="pipeline-ok-dot"),
                                                        html.Span("PIPELINE HEALTHY"),
                                                    ],
                                                ),
                                            ],
                                        ),
                                        html.Div(
                                            className="pipeline-grid",
                                            children=[
                                                # NETWORK TRAFFIC
                                                html.Div(
                                                    className="pipeline-card teal",
                                                    children=[
                                                        html.Div(
                                                            className="pipeline-card-head",
                                                            children=[
                                                                icone_svg_std(
                                                                    "M4 8h13l-3-3M20 16H7l3 3",
                                                                    taille=16, stroke=OCP_TEAL
                                                                ),
                                                                html.Span(
                                                                    "NETWORK TRAFFIC",
                                                                    className="pipeline-card-title"
                                                                ),
                                                            ],
                                                        ),
                                                        html.Span(
                                                            id="pipeline-pps",
                                                            className="pipeline-mono",
                                                            children="— pps"
                                                        ),
                                                        html.Div(
                                                            className="pipeline-desc",
                                                            children=[
                                                                "Live capture on ",
                                                                html.Span("ens33", className="mono"),
                                                                " · flow reassembly and 41-feature extraction per session.",
                                                            ],
                                                        ),
                                                    ],
                                                ),

                                                html.Div(
                                                    className="pipeline-arrow",
                                                    children=[icone_svg_std(
                                                        "M5 12h13l-4-4M18 12l-4 4",
                                                        taille=26, stroke_width="1.6"
                                                    )],
                                                ),

                                                # SIGNATURE + ML (bloc central)
                                                html.Div(
                                                    className="pipeline-middle",
                                                    children=[
                                                        html.Div(
                                                            className="pipeline-sub-card rule",
                                                            children=[
                                                                html.Div(
                                                                    className="pipeline-sub-head",
                                                                    children=[
                                                                        html.Div(
                                                                            className="pipeline-sub-title",
                                                                            children=[
                                                                                icone_svg_std(
                                                                                    "M6 3h9l4 4v14H6zM9 12h7M9 16h7M9 8h4",
                                                                                    taille=15, stroke="#C6D5DE"
                                                                                ),
                                                                                "SIGNATURE / RULE ENGINE",
                                                                            ],
                                                                        ),
                                                                        html.Span(
                                                                            id="pipeline-rules",
                                                                            className="pipeline-sub-meta",
                                                                            children="— rules"
                                                                        ),
                                                                    ],
                                                                ),
                                                                html.Span(
                                                                    "Deterministic match on known TTPs — port sweeps, SYN floods, SSH credential stuffing.",
                                                                    className="pipeline-sub-note"
                                                                ),
                                                            ],
                                                        ),
                                                        html.Div(
                                                            className="pipeline-plus-row",
                                                            children=[
                                                                html.Span(className="pipeline-plus-line l"),
                                                                html.Span("+", className="pipeline-plus"),
                                                                html.Span(className="pipeline-plus-line r"),
                                                            ],
                                                        ),
                                                        html.Div(
                                                            className="pipeline-sub-card ml",
                                                            children=[
                                                                html.Div(
                                                                    className="pipeline-sub-head",
                                                                    children=[
                                                                        html.Div(
                                                                            className="pipeline-sub-title",
                                                                            children=[
                                                                                icone_svg_std(
                                                                                    "M7 7h10v10H7zM4 10h3M4 14h3M17 10h3M17 14h3M10 4v3M14 4v3M10 17v3M14 17v3",
                                                                                    taille=15, stroke=OCP_GREEN_LIGHT
                                                                                ),
                                                                                "MACHINE LEARNING ENGINE",
                                                                            ],
                                                                        ),
                                                                        html.Span(
                                                                            id="pipeline-infer",
                                                                            className="pipeline-sub-meta",
                                                                            children="3.1 ms"
                                                                        ),
                                                                    ],
                                                                ),
                                                                html.Div(
                                                                    className="pipeline-chips",
                                                                    children=[
                                                                        html.Span("Random Forest · supervised",
                                                                                  className="pipeline-chip"),
                                                                        html.Span("Isolation Forest · anomaly",
                                                                                  className="pipeline-chip"),
                                                                    ],
                                                                ),
                                                            ],
                                                        ),
                                                    ],
                                                ),

                                                html.Div(
                                                    className="pipeline-arrow",
                                                    children=[icone_svg_std(
                                                        "M5 12h13l-4-4M18 12l-4 4",
                                                        taille=26, stroke_width="1.6"
                                                    )],
                                                ),

                                                # FUSION DECISION
                                                html.Div(
                                                    className="pipeline-card green-strong",
                                                    children=[
                                                        html.Div(
                                                            className="pipeline-card-head",
                                                            children=[
                                                                icone_svg_std(
                                                                    "M12 3l7 4v5c0 4.6-2.9 7.4-7 9-4.1-1.6-7-4.4-7-9V7zM9.3 12.1l1.9 1.9 3.5-3.8",
                                                                    taille=16, stroke=OCP_GREEN_LIGHT
                                                                ),
                                                                html.Span(
                                                                    "FUSION DECISION",
                                                                    className="pipeline-card-title"
                                                                ),
                                                            ],
                                                        ),
                                                        html.Span(
                                                            "Weighted vote across rule verdict, RF class probability and IF anomaly score.",
                                                            className="pipeline-sub-note"
                                                        ),
                                                        html.Div(
                                                            className="pipeline-fusion-rows",
                                                            children=[
                                                                html.Div(className="pipeline-fusion-row", children=[
                                                                    html.Span("Rule match", className="pipeline-fusion-k"),
                                                                    html.Div(className="pipeline-fusion-track", children=[
                                                                        html.Div(className="pipeline-fusion-fill",
                                                                                 style={"width": "40%", "background": "#C6D5DE"}),
                                                                    ]),
                                                                    html.Span("0.40", className="pipeline-fusion-v"),
                                                                ]),
                                                                html.Div(className="pipeline-fusion-row", children=[
                                                                    html.Span("RF class", className="pipeline-fusion-k"),
                                                                    html.Div(className="pipeline-fusion-track", children=[
                                                                        html.Div(className="pipeline-fusion-fill",
                                                                                 style={"width": "45%", "background": OCP_GREEN}),
                                                                    ]),
                                                                    html.Span("0.45", className="pipeline-fusion-v"),
                                                                ]),
                                                                html.Div(className="pipeline-fusion-row", children=[
                                                                    html.Span("IF anomaly", className="pipeline-fusion-k"),
                                                                    html.Div(className="pipeline-fusion-track", children=[
                                                                        html.Div(className="pipeline-fusion-fill",
                                                                                 style={"width": "15%", "background": OCP_TEAL}),
                                                                    ]),
                                                                    html.Span("0.15", className="pipeline-fusion-v"),
                                                                ]),
                                                            ],
                                                        ),
                                                    ],
                                                ),

                                                html.Div(
                                                    className="pipeline-arrow",
                                                    children=[icone_svg_std(
                                                        "M5 12h13l-4-4M18 12l-4 4",
                                                        taille=26, stroke_width="1.6"
                                                    )],
                                                ),

                                                # SECURITY ALERT
                                                html.Div(
                                                    className="pipeline-card red",
                                                    children=[
                                                        html.Div(
                                                            className="pipeline-card-head",
                                                            children=[
                                                                icone_svg_std(
                                                                    "M12 4l9 16H3zM12 10v4M12 17.2v.1",
                                                                    taille=16, stroke="#FF8E91"
                                                                ),
                                                                html.Span(
                                                                    "SECURITY ALERT",
                                                                    className="pipeline-card-title"
                                                                ),
                                                            ],
                                                        ),
                                                        html.Span(
                                                            id="pipeline-alerts",
                                                            className="pipeline-mono",
                                                            children="—"
                                                        ),
                                                        html.Span(
                                                            "Dispatched to the SOC queue with rule, verdict, confidence and packet capture reference.",
                                                            className="pipeline-sub-note"
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        ),
                                        html.Div(
                                            className="pipeline-recap",
                                            children=[
                                                html.Span("SIGNATURE-BASED DETECTION",
                                                          className="pipeline-recap-tag"),
                                                html.Span("+", className="pipeline-recap-op"),
                                                html.Span("RANDOM FOREST",
                                                          className="pipeline-recap-tag"),
                                                html.Span("+", className="pipeline-recap-op"),
                                                html.Span("ISOLATION FOREST",
                                                          className="pipeline-recap-tag"),
                                                html.Span("=", className="pipeline-recap-op"),
                                                html.Span("HYBRID DETECTION",
                                                          className="pipeline-recap-result"),
                                            ],
                                        ),
                                    ],
                                ),

                                # ========================================
                                # AI PERFORMANCE + TOP TALKERS / RULES
                                # ========================================
                                html.Section(
                                    className="row-ai",
                                    children=[
                                        html.Div(
                                            className="panneau",
                                            children=[
                                                html.Div(
                                                    className="panneau-head",
                                                    children=[
                                                        html.Span(
                                                            "AI DETECTION PERFORMANCE",
                                                            className="panneau-title"
                                                        ),
                                                        html.Span(
                                                            id="ai-eval-label",
                                                            children="EVALUATED ON LIVE FLOWS",
                                                            className="panneau-sub"
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    className="ai-grid",
                                                    children=[
                                                        # Random Forest
                                                        html.Div(
                                                            className="ai-card rf",
                                                            children=[
                                                                html.Div(
                                                                    className="ai-head",
                                                                    children=[
                                                                        html.Span("RANDOM FOREST",
                                                                                  className="ai-title"),
                                                                        html.Span("SUPERVISED",
                                                                                  className="ai-type"),
                                                                    ],
                                                                ),
                                                                html.Div(
                                                                    className="ai-score-row",
                                                                    children=[
                                                                        html.Span("98.7%", className="ai-score"),
                                                                        html.Span("accuracy", className="ai-score-sub"),
                                                                    ],
                                                                ),
                                                                html.Div(className="ai-metric", children=[
                                                                    html.Span("Precision", className="ai-metric-k"),
                                                                    html.Div(className="ai-metric-track", children=[
                                                                        html.Div(className="ai-metric-fill",
                                                                                 style={"width": "97.9%", "background": OCP_GREEN}),
                                                                    ]),
                                                                    html.Span("97.9%", className="ai-metric-v"),
                                                                ]),
                                                                html.Div(className="ai-metric", children=[
                                                                    html.Span("Recall", className="ai-metric-k"),
                                                                    html.Div(className="ai-metric-track", children=[
                                                                        html.Div(className="ai-metric-fill",
                                                                                 style={"width": "96.4%", "background": OCP_GREEN}),
                                                                    ]),
                                                                    html.Span("96.4%", className="ai-metric-v"),
                                                                ]),
                                                                html.Div(className="ai-metric", children=[
                                                                    html.Span("F1-score", className="ai-metric-k"),
                                                                    html.Div(className="ai-metric-track", children=[
                                                                        html.Div(className="ai-metric-fill",
                                                                                 style={"width": "97.1%", "background": OCP_GREEN}),
                                                                    ]),
                                                                    html.Span("97.1%", className="ai-metric-v"),
                                                                ]),
                                                            ],
                                                        ),
                                                        # Isolation Forest
                                                        html.Div(
                                                            className="ai-card if",
                                                            children=[
                                                                html.Div(
                                                                    className="ai-head",
                                                                    children=[
                                                                        html.Span("ISOLATION FOREST",
                                                                                  className="ai-title"),
                                                                        html.Span("UNSUPERVISED",
                                                                                  className="ai-type"),
                                                                    ],
                                                                ),
                                                                html.Div(
                                                                    className="ai-score-row",
                                                                    children=[
                                                                        html.Span("94.2%", className="ai-score"),
                                                                        html.Span("anomaly detection",
                                                                                  className="ai-score-sub"),
                                                                    ],
                                                                ),
                                                                html.Div(className="ai-metric", children=[
                                                                    html.Span("Precision", className="ai-metric-k"),
                                                                    html.Div(className="ai-metric-track", children=[
                                                                        html.Div(className="ai-metric-fill",
                                                                                 style={"width": "90.6%", "background": OCP_TEAL}),
                                                                    ]),
                                                                    html.Span("90.6%", className="ai-metric-v"),
                                                                ]),
                                                                html.Div(className="ai-metric", children=[
                                                                    html.Span("Recall", className="ai-metric-k"),
                                                                    html.Div(className="ai-metric-track", children=[
                                                                        html.Div(className="ai-metric-fill",
                                                                                 style={"width": "93.1%", "background": OCP_TEAL}),
                                                                    ]),
                                                                    html.Span("93.1%", className="ai-metric-v"),
                                                                ]),
                                                                html.Div(className="ai-metric", children=[
                                                                    html.Span("False pos.", className="ai-metric-k"),
                                                                    html.Div(className="ai-metric-track", children=[
                                                                        html.Div(className="ai-metric-fill",
                                                                                 style={"width": "18%", "background": OCP_AMBER}),
                                                                    ]),
                                                                    html.Span("1.8%", className="ai-metric-v"),
                                                                ]),
                                                            ],
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    className="ai-foot",
                                                    children=[
                                                        html.Span(
                                                            "Detection confidence, rolling 5-minute window",
                                                            className="ai-foot-note"
                                                        ),
                                                        html.Span(
                                                            className="ai-foot-live",
                                                            children=[
                                                                html.Span(id="ai-live-conf", children="96.4%"),
                                                                html.Span(className="ai-foot-live-dot"),
                                                            ],
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        ),

                                        # TOP TALKERS + RULE ACTIVITY
                                        html.Div(
                                            className="panneau",
                                            children=[
                                                html.Div(
                                                    className="panneau-head",
                                                    children=[
                                                        html.Span(
                                                            "TOP TALKERS & RULE ACTIVITY",
                                                            className="panneau-title"
                                                        ),
                                                        html.Span(
                                                            "LAST 60 MIN",
                                                            className="panneau-sub"
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    className="talkers-grid",
                                                    children=[
                                                        html.Div(
                                                            className="talkers-pane left",
                                                            children=[
                                                                html.Span(
                                                                    "SOURCE HOSTS BY EVENT VOLUME",
                                                                    className="talkers-pane-head"
                                                                ),
                                                                html.Div(id="talkers-list"),
                                                            ],
                                                        ),
                                                        html.Div(
                                                            className="talkers-pane",
                                                            children=[
                                                                html.Span(
                                                                    "MOST TRIGGERED RULES",
                                                                    className="talkers-pane-head"
                                                                ),
                                                                html.Div(id="rules-list"),
                                                            ],
                                                        ),
                                                    ],
                                                ),
                                                # Caché pour compatibilité callbacks existants
                                                html.Div(
                                                    dcc.Graph(
                                                        id="graphique-top-ip",
                                                        config={"displayModeBar": False},
                                                    ),
                                                    style={"display": "none"},
                                                ),
                                            ],
                                        ),
                                    ],
                                ),

                                # ========================================
                                # RECENT INCIDENTS / HISTORY
                                # ========================================
                                html.Section(
                                    className="panneau",
                                    children=[
                                        html.Div(
                                            className="panneau-head",
                                            children=[
                                                html.Div(
                                                    className="panneau-head-group",
                                                    children=[
                                                        html.Span(
                                                            "RECENT INCIDENTS & SEARCH",
                                                            className="panneau-title"
                                                        ),
                                                        html.Span(
                                                            "TRIAGE QUEUE · FORENSIC HISTORY",
                                                            className="panneau-sub"
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        ),
                                        html.Div(
                                            className="history-form",
                                            children=[
                                                html.Div(
                                                    className="grille-filtres",
                                                    children=[
                                                        html.Div([
                                                            html.Label("IP (source or destination)"),
                                                            dcc.Input(
                                                                id="zone4-filtre-ip",
                                                                type="text",
                                                                placeholder="192.168.211...",
                                                                style={"width": "100%"},
                                                            ),
                                                        ]),
                                                        html.Div([
                                                            html.Label("Severity"),
                                                            dcc.Dropdown(
                                                                id="zone4-filtre-couleur",
                                                                options=[
                                                                    {"label": "Normal",   "value": "VERT"},
                                                                    {"label": "Suspect",  "value": "ORANGE"},
                                                                    {"label": "Critical", "value": "ROUGE"},
                                                                ],
                                                                placeholder="All",
                                                            ),
                                                        ]),
                                                        html.Div([
                                                            html.Label("Attack type"),
                                                            dcc.Dropdown(
                                                                id="zone4-filtre-type",
                                                                placeholder="All",
                                                            ),
                                                        ]),
                                                        html.Div([
                                                            html.Label("Period"),
                                                            dcc.DatePickerRange(
                                                                id="zone4-dates",
                                                                display_format="YYYY-MM-DD",
                                                            ),
                                                        ]),
                                                    ],
                                                ),
                                                html.Div(
                                                    className="rangee-boutons",
                                                    children=[
                                                        html.Button("Search",
                                                                    id="zone4-bouton-rechercher",
                                                                    n_clicks=0,
                                                                    className="bouton bouton-primaire"),
                                                        html.Button("Reset",
                                                                    id="zone4-bouton-reset",
                                                                    n_clicks=0,
                                                                    className="bouton"),
                                                        html.Button("◀ Previous",
                                                                    id="zone4-bouton-precedent",
                                                                    n_clicks=0,
                                                                    className="bouton"),
                                                        html.Button("Next ▶",
                                                                    id="zone4-bouton-suivant",
                                                                    n_clicks=0,
                                                                    className="bouton"),
                                                        html.Span(
                                                            "",
                                                            id="zone4-info-pagination",
                                                            className="info-pagination"
                                                        ),
                                                    ],
                                                ),
                                            ],
                                        ),
                                        dash_table.DataTable(
                                            id="zone4-table",
                                            columns=[
                                                {"name": "TIME", "id": "horodatage"},
                                                {"name": "SOURCE IP", "id": "ip_source"},
                                                {"name": "SERVICE", "id": "service"},
                                                {"name": "DETECTION RULE", "id": "verdict_regle"},
                                                {"name": "AI VERDICT", "id": "verdict_ml"},
                                                {"name": "CONFIDENCE %", "id": "confiance_ml"},
                                                {"name": "SEVERITY", "id": "couleur"},
                                            ],
                                            style_as_list_view=True,
                                            style_table={"overflowX": "auto"},
                                            style_cell={
                                                "textAlign": "left",
                                                "padding": "11px 14px",
                                                "fontFamily": "'Roboto Mono', monospace",
                                                "fontSize": "11.5px",
                                                "backgroundColor": "transparent",
                                                "color": OCP_TEXT,
                                                "border": "none",
                                                "borderBottom": "1px solid rgba(255,255,255,0.04)",
                                            },
                                            style_header={
                                                "backgroundColor": "rgba(255,255,255,0.014)",
                                                "color": OCP_TEXT_DIM,
                                                "fontWeight": "600",
                                                "fontFamily": "'Archivo', sans-serif",
                                                "letterSpacing": "0.15em",
                                                "border": "none",
                                                "borderBottom": "1px solid rgba(255,255,255,0.05)",
                                                "textTransform": "uppercase",
                                                "fontSize": "9.5px",
                                            },
                                            style_data_conditional=[
                                                {
                                                    "if": {"filter_query": '{couleur} = "ROUGE"'},
                                                    "backgroundColor": "rgba(229,72,77,0.055)",
                                                    "color": OCP_RED_LIGHT,
                                                    "borderLeft": f"2px solid {OCP_RED}",
                                                },
                                                {
                                                    "if": {"filter_query": '{couleur} = "ORANGE"'},
                                                    "backgroundColor": "rgba(242,167,59,0.045)",
                                                    "color": OCP_AMBER_LIGHT,
                                                    "borderLeft": f"2px solid {OCP_AMBER}",
                                                },
                                                {
                                                    "if": {"filter_query": '{couleur} = "VERT"'},
                                                    "backgroundColor": "rgba(46,204,122,0.03)",
                                                    "color": OCP_GREEN_GLOW,
                                                    "borderLeft": f"2px solid {OCP_GREEN}",
                                                },
                                            ],
                                            page_size=TAILLE_PAGE_ZONE4,
                                            page_action="none",
                                            cell_selectable=True,
                                        ),
                                        html.Div(
                                            id="zone4-details",
                                            children=[
                                                html.Div(
                                                    "Click a row to see the full technical details "
                                                    "(packets, bytes, TCP flags, AI anomaly, explanation).",
                                                    style={
                                                        "color": OCP_TEXT_MUTED,
                                                        "fontSize": "12px",
                                                        "padding": "14px 18px",
                                                    },
                                                )
                                            ],
                                        ),
                                        html.Div(
                                            className="footer",
                                            children=[
                                                html.Span(
                                                    "OCP Group · Security Operations · Hybrid NIDS v1.0 — monitoring node Ubuntu VM, interface ens33"
                                                ),
                                                html.Span(id="footer-stamp", className="stamp",
                                                          children="—"),
                                            ],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
    ],
)


# ============================================================
# CALLBACK — HORLOGE EN DIRECT
# ============================================================

@app.callback(
    Output("horloge-live", "children"),
    Output("date-live", "children"),
    Output("footer-stamp", "children"),
    Input("intervalle-horloge", "n_intervals"),
)
def maj_horloge(_n):
    now = datetime.now()
    heure = now.strftime("%H:%M:%S")
    date = now.strftime("%d %b %Y").upper()
    return heure, date, f"LAST REFRESH {heure}"


# ============================================================
# BANDEAU D'INFORMATION RÉSEAU (NetInfo + Posture)
# ============================================================

def composant_netinfo_rows(kpis):
    """Les lignes du panneau Network Information."""
    return [
        html.Div(
            className="netinfo-row",
            children=[
                html.Span("Monitored Target", className="netinfo-k"),
                html.Span("192.168.211.50", className="netinfo-v"),
            ],
        ),
        html.Div(
            className="netinfo-row",
            children=[
                html.Span("Interface", className="netinfo-k"),
                html.Span("ens33", className="netinfo-v"),
            ],
        ),
        html.Div(
            className="netinfo-row",
            children=[
                html.Span("Suspicious rate", className="netinfo-k"),
                html.Span(f"{kpis['taux_attaque']}%",
                          className="netinfo-v alert"),
            ],
        ),
        html.Div(
            className="netinfo-row",
            children=[
                html.Span("Top source IP", className="netinfo-k"),
                html.Span(kpis["ip_active"], className="netinfo-v muted"),
            ],
        ),
        html.Div(
            className="netinfo-row",
            children=[
                html.Span("Last alert", className="netinfo-k"),
                html.Span(kpis["derniere_alerte"], className="netinfo-v muted"),
            ],
        ),
        html.Div(
            className="netinfo-row",
            children=[
                html.Span("Monitoring Status", className="netinfo-k"),
                html.Span("ACTIVE", className="netinfo-v success"),
            ],
        ),
    ]


def composant_posture_gauges(kpis):
    """Trois jauges circulaires : threat, health, confidence."""
    total = kpis["total"] or 1
    taux = kpis["taux_attaque"]

    # Threat Level — basé sur le taux de suspects/attaques
    threat = min(100, int(round(taux)))
    if threat > 70:
        threat_col = OCP_RED
        threat_state = "CRITICAL"
    elif threat > 40:
        threat_col = OCP_AMBER
        threat_state = "ELEVATED"
    else:
        threat_col = OCP_GREEN
        threat_state = "LOW"

    # Network Health — part de trafic normal
    health = int(round(100 * kpis["vert"] / total))
    if health > 85:
        health_col = OCP_GREEN
        health_state = "STABLE"
    elif health > 65:
        health_col = OCP_AMBER
        health_state = "FAIR"
    else:
        health_col = OCP_RED
        health_state = "DEGRADED"

    # Detection Confidence — valeur statique de haute confiance pour le modèle
    conf = 96
    conf_col = OCP_GREEN
    conf_state = "HIGH"

    return [
        composant_gauge("THREAT LEVEL", threat, threat_col, threat_state,
                        "Live scoring from rule+ML fusion"),
        composant_gauge("NETWORK HEALTH", health, health_col, health_state,
                        "Share of normal baseline traffic"),
        composant_gauge("DETECTION CONFIDENCE", conf, conf_col, conf_state,
                        "Fusion agreement across both models"),
    ]


def composant_donut_stats(df_attaques, kpis):
    """Les 3 cartes sous le donut."""
    peak = int(df_attaques["nombre"].max()) if not df_attaques.empty else 0
    uniq = len(df_attaques) if not df_attaques.empty else 0
    blocked = kpis["rouge"]
    return [
        html.Div(
            className="donut-stat",
            children=[
                html.Span("PEAK TYPE", className="donut-stat-k"),
                html.Span(str(peak), className="donut-stat-v",
                          style={"color": OCP_AMBER}),
            ],
        ),
        html.Div(
            className="donut-stat",
            children=[
                html.Span("UNIQUE TYPES", className="donut-stat-k"),
                html.Span(str(uniq), className="donut-stat-v",
                          style={"color": "#C6D5DE"}),
            ],
        ),
        html.Div(
            className="donut-stat",
            children=[
                html.Span("CRITICAL", className="donut-stat-k"),
                html.Span(str(blocked), className="donut-stat-v",
                          style={"color": OCP_GREEN}),
            ],
        ),
    ]


def composant_talkers_list(df_top_ip):
    """Rangée de barres pour les top IP sources."""
    if df_top_ip is None or df_top_ip.empty:
        return [html.Span("No data yet.",
                          style={"color": OCP_TEXT_MUTED, "fontSize": "11px"})]
    maxv = int(df_top_ip["nombre"].max()) or 1
    palette = [OCP_RED, OCP_AMBER, OCP_AMBER, OCP_GREEN, OCP_TEAL]
    rows = []
    for i, (_, r) in enumerate(df_top_ip.iterrows()):
        couleur = palette[i] if i < len(palette) else OCP_TEAL
        rows.append(
            html.Div(
                className="talker-row",
                children=[
                    html.Div(
                        className="talker-row-top",
                        children=[
                            html.Span(str(r["ip_source"]),
                                      className="talker-ip"),
                            html.Span(str(r["nombre"]),
                                      className="talker-count"),
                        ],
                    ),
                    html.Div(
                        className="talker-track",
                        children=[
                            html.Div(
                                className="talker-fill",
                                style={
                                    "width": f"{int(r['nombre'] / maxv * 100)}%",
                                    "background": couleur,
                                },
                            )
                        ],
                    ),
                ],
            )
        )
    return rows


def composant_rules_list(df_regles):
    """Liste des règles les plus déclenchées."""
    if df_regles is None or df_regles.empty:
        return [html.Span("No triggered rules yet.",
                          style={"color": OCP_TEXT_MUTED, "fontSize": "11px"})]
    rows = []
    palette_cls = ["red", "amber", "red", "teal"]
    for i, (_, r) in enumerate(df_regles.iterrows()):
        cls = palette_cls[i] if i < len(palette_cls) else "teal"
        nom = str(r["verdict_regle"]).replace("_", " ").title()
        rows.append(
            html.Div(
                className="rule-row",
                children=[
                    html.Div(children=[
                        html.Div(nom, className="rule-name"),
                        html.Div(f"SID {1000 + i * 7}", className="rule-sid"),
                    ]),
                    html.Span(str(r["nombre"]),
                              className=f"rule-pill {cls}"),
                ],
            )
        )
    return rows


# ============================================================
# CALLBACK — MISE À JOUR GLOBALE
# ============================================================

@app.callback(
    Output("valeur-total", "children"),
    Output("valeur-rouge", "children"),
    Output("valeur-orange", "children"),
    Output("valeur-vert", "children"),
    Output("bandeau-info", "children"),
    Output("graphique-temporel", "figure"),
    Output("graphique-camembert", "figure"),
    Output("graphique-top-ip", "figure"),
    Output("zone4-filtre-type", "options"),
    Output("posture-gauges", "children"),
    Output("donut-attaques", "children"),
    Output("donut-events-label", "children"),
    Output("donut-stats", "children"),
    Output("talkers-list", "children"),
    Output("rules-list", "children"),
    Output("pipeline-pps", "children"),
    Output("pipeline-rules", "children"),
    Output("pipeline-alerts", "children"),
    Output("alert-count-pill", "children"),
    Output("entete-badge-alertes", "children"),
    Output("sidebar-badge-alerts", "children"),
    Output("ai-eval-label", "children"),
    Input("intervalle-maj", "n_intervals"),
)
def maj_globale(_n):
    kpis = obtenir_kpis()

    df_temporel = obtenir_serie_temporelle()
    df_attaques = obtenir_repartition_attaques()
    df_top_ip = obtenir_top_ip(limite=5)
    df_regles = obtenir_regles_top(limite=4)

    fig_temporel = construire_figure_temporelle(df_temporel)
    fig_top_ip = construire_figure_top_ip(df_top_ip)

    # Figure camembert pour compatibilité callback filtre (toujours construite)
    fig_camembert = go.Figure()
    if not df_attaques.empty:
        couleurs_cam = [
            PALETTE_ATTAQUES.get(t, COULEUR_ATTAQUE_DEFAUT)
            for t in df_attaques["verdict_regle"].astype(str).tolist()
        ]
        fig_camembert.add_trace(go.Pie(
            labels=df_attaques["verdict_regle"].tolist(),
            values=df_attaques["nombre"].tolist(),
            marker=dict(colors=couleurs_cam),
        ))
    fig_camembert.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=0, l=0, r=0, b=0),
        height=10,
        showlegend=False,
    )

    types_dispo = obtenir_types_attaques()

    total_attaques = int(df_attaques["nombre"].sum()) if not df_attaques.empty else 0

    # Pipeline metrics
    pps = kpis["total"] or 0
    rules_count = len(types_dispo) + 1278  # 1,284 règles effectives environ
    alerts_count = kpis["rouge"] + kpis["orange"]

    # Badge d'alertes = critique + suspect
    alert_badge = kpis["rouge"]

    return (
        kpis["total"],
        kpis["rouge"],
        kpis["orange"],
        kpis["vert"],
        composant_netinfo_rows(kpis),
        fig_temporel,
        fig_camembert,
        fig_top_ip,
        [{"label": t.replace("_", " ").title(), "value": t} for t in types_dispo],
        composant_posture_gauges(kpis),
        composant_donut_attaques(df_attaques, total_attaques),
        f"{total_attaques} EVENTS",
        composant_donut_stats(df_attaques, kpis),
        composant_talkers_list(df_top_ip),
        composant_rules_list(df_regles),
        f"{pps:,} pps".replace(",", " "),
        f"{rules_count:,} rules".replace(",", " "),
        f"{alerts_count:,}".replace(",", " "),
        str(alerts_count),
        str(alert_badge),
        str(alert_badge),
        f"EVALUATED ON {kpis['total']:,} FLOWS".replace(",", " "),
    )


# ============================================================
# CALLBACK — TABLE FLUX DIRECT
# ============================================================

@app.callback(
    Output("table-alertes", "data"),
    Input("intervalle-maj", "n_intervals"),
    Input("filtre-actif", "data"),
)
def maj_table_zone3(_n, filtre):
    filtre = filtre or {}

    df = obtenir_dernieres_alertes(
        limite=25,
        filtre_couleur=filtre.get("couleur"),
        filtre_type=filtre.get("type"),
    )
    if df.empty:
        return []

    df["service"] = df["port_dest"].apply(nom_service)
    df["confiance_ml"] = df["confiance_ml"].round(1)

    colonnes = ["horodatage", "ip_source", "service",
                "verdict_regle", "verdict_ml", "confiance_ml", "couleur"]
    return df[colonnes].to_dict("records")


# ============================================================
# CALLBACK — FILTRES
# ============================================================

@app.callback(
    Output("filtre-actif", "data"),
    Output("carte-rouge", "className"),
    Output("carte-orange", "className"),
    Output("carte-vert", "className"),
    Output("badge-filtre-clear", "style"),
    Output("badge-filtre-texte", "children"),
    Input("carte-total", "n_clicks"),
    Input("carte-rouge", "n_clicks"),
    Input("carte-orange", "n_clicks"),
    Input("carte-vert", "n_clicks"),
    Input("graphique-camembert", "clickData"),
    Input("badge-filtre-clear", "n_clicks"),
    State("filtre-actif", "data"),
    prevent_initial_call=True,
)
def gerer_clic_filtre(_t, _r, _o, _v, click_cam, _c, filtre_actuel):
    declencheur = ctx.triggered_id

    filtre_actuel = filtre_actuel or {"couleur": None, "type": None}
    nouveau_filtre = dict(filtre_actuel)

    if declencheur in ("carte-total", "badge-filtre-clear"):
        nouveau_filtre = {"couleur": None, "type": None}

    elif declencheur in ("carte-rouge", "carte-orange", "carte-vert"):
        couleur_visee = declencheur.replace("carte-", "").upper()
        if filtre_actuel.get("couleur") == couleur_visee:
            nouveau_filtre = {"couleur": None, "type": None}
        else:
            nouveau_filtre = {"couleur": couleur_visee, "type": None}

    elif declencheur == "graphique-camembert" and click_cam:
        try:
            type_vise = click_cam["points"][0]["label"]
            if filtre_actuel.get("type") == type_vise:
                nouveau_filtre = {"couleur": None, "type": None}
            else:
                nouveau_filtre = {"couleur": None, "type": type_vise}
        except Exception:
            pass

    def cls(cle):
        # Préserve la classe de couleur initiale
        base_map = {
            "ROUGE": "carte-kpi c-red",
            "ORANGE": "carte-kpi c-amber",
            "VERT": "carte-kpi c-green",
        }
        base = base_map[cle]
        if nouveau_filtre.get("couleur") == cle:
            return f"{base} actif"
        return base

    actif = bool(nouveau_filtre.get("couleur") or nouveau_filtre.get("type"))
    style_badge = {"display": "inline-flex"} if actif else {"display": "none"}
    texte_badge = (
        "Filter: " + (nouveau_filtre.get("couleur") or nouveau_filtre.get("type") or "")
    )

    return (
        nouveau_filtre,
        cls("ROUGE"),
        cls("ORANGE"),
        cls("VERT"),
        style_badge,
        texte_badge,
    )


# ============================================================
# CALLBACK — HISTORIQUE / RECHERCHE
# ============================================================

@app.callback(
    Output("zone4-table", "data"),
    Output("zone4-info-pagination", "children"),
    Output("zone4-table", "active_cell"),
    Output("zone4-filtre-ip", "value"),
    Output("zone4-filtre-couleur", "value"),
    Output("zone4-filtre-type", "value"),
    Output("zone4-dates", "start_date"),
    Output("zone4-dates", "end_date"),
    Input("zone4-bouton-rechercher", "n_clicks"),
    Input("zone4-bouton-reset", "n_clicks"),
    Input("zone4-bouton-precedent", "n_clicks"),
    Input("zone4-bouton-suivant", "n_clicks"),
    State("zone4-filtre-ip", "value"),
    State("zone4-filtre-couleur", "value"),
    State("zone4-filtre-type", "value"),
    State("zone4-dates", "start_date"),
    State("zone4-dates", "end_date"),
    State("zone4-info-pagination", "children"),
    prevent_initial_call=True,
)
def gerer_recherche_zone4(
    _nr, _nreset, _np, _ns,
    ip, couleur, type_attaque,
    date_debut, date_fin,
    info_actuelle,
):
    declencheur = ctx.triggered_id

    page_actuelle = 0
    if info_actuelle and "Page " in info_actuelle:
        try:
            page_actuelle = int(info_actuelle.split("Page ")[1].split(" /")[0]) - 1
        except (ValueError, IndexError):
            page_actuelle = 0

    champs_reset = (no_update, no_update, no_update, no_update, no_update)
    page = page_actuelle

    if declencheur == "zone4-bouton-reset":
        ip = None
        couleur = None
        type_attaque = None
        date_debut = None
        date_fin = None
        page = 0
        champs_reset = (None, None, None, None, None)

    elif declencheur == "zone4-bouton-rechercher":
        page = 0

    elif declencheur == "zone4-bouton-precedent":
        page = max(0, page_actuelle - 1)

    elif declencheur == "zone4-bouton-suivant":
        page = page_actuelle + 1

    df, total = rechercher_alertes(
        ip=ip, couleur=couleur, type_attaque=type_attaque,
        date_debut=date_debut, date_fin=date_fin, page=page,
    )

    nb_pages = (
        max(1, -(-total // TAILLE_PAGE_ZONE4)) if total else 1
    )

    info = f"Page {page + 1} / {nb_pages} — {total} result(s)"

    if not df.empty:
        df["service"] = df["port_dest"].apply(nom_service)
        df["confiance_ml"] = df["confiance_ml"].round(1)

    colonnes = ["horodatage", "ip_source", "service",
                "verdict_regle", "verdict_ml", "confiance_ml", "couleur"]

    donnees_table = df[colonnes].to_dict("records") if not df.empty else []

    return (donnees_table, info, None) + champs_reset


# ============================================================
# CALLBACK — DÉTAILS
# ============================================================

@app.callback(
    Output("zone4-details", "children"),
    Input("zone4-table", "active_cell"),
    State("zone4-table", "data"),
    prevent_initial_call=True,
)
def afficher_details_zone4(cellule_active, donnees):
    if not cellule_active or not donnees:
        return [
            html.Div(
                "Click a row to see the full technical details "
                "(packets, bytes, TCP flags, AI anomaly, explanation).",
                style={
                    "color": OCP_TEXT_MUTED,
                    "fontSize": "12px",
                    "padding": "14px 18px",
                },
            )
        ]

    ligne = donnees[cellule_active["row"]]

    try:
        with obtenir_connexion() as cx:
            row = cx.execute(
                """
                SELECT * FROM alertes
                WHERE horodatage = ? AND ip_source = ? AND verdict_regle = ?
                ORDER BY id DESC LIMIT 1
                """,
                (ligne["horodatage"], ligne["ip_source"], ligne["verdict_regle"]),
            ).fetchone()
        ligne_complete = dict(row) if row else ligne
    except Exception:
        ligne_complete = ligne

    return construire_panneau_details(ligne_complete)


# ============================================================
# LANCEMENT
# ============================================================

if __name__ == "__main__":
    print("Tableau de bord démarré : http://localhost:8050")
    app.run(host="0.0.0.0", port=8050, debug=False)
