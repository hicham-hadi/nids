import sqlite3
import pandas as pd
import dash
from dash import dcc, html, dash_table, ctx, no_update
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.graph_objs as go


# ============================================================
# MODULE 7 — TABLEAU DE BORD WEB
# NIDS HYBRIDE — OCP GROUP
# ============================================================

FICHIER_DB = "nids_alertes.db"

# ============================================================
# COULEURS
# ============================================================

OCP_GREEN = "#1E6B33"
OCP_BLUE = "#1F4E79"

COULEURS = {
    "VERT": "#2ECC71",
    "ORANGE": "#F39C12",
    "ROUGE": "#E74C3C",
}

TOTAL_ACCENT = "#4FA3E3"

PALETTE_ATTAQUES = {
    "PORT_SCAN": "#F59E0B",
    "DOS_SYN_FLOOD": "#A855F7",
    "BRUTE_FORCE_SSH": "#EF4444",
    "BRUTE_FORCE_FTP": "#06B6D4",
    "BRUTE_FORCE_HTTP": "#EC4899",
    "DNS_TUNNELING": "#84CC16",
    "ICMP_FLOOD": "#F97316",
}

COULEURS_ATTAQUES_SUPPLEMENTAIRES = [
    "#14B8A6",
    "#6366F1",
    "#EAB308",
    "#F43F5E",
    "#22C55E",
]

COULEUR_ATTAQUE_DEFAUT = "#60A5FA"

FOND_GRAPHIQUE = "#141B2E"
TEXTE_GRAPHIQUE = "#E7ECF3"
GRILLE_GRAPHIQUE = "#223052"

SERVICES_CONNUS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
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
                "total": 0,
                "rouge": 0,
                "orange": 0,
                "vert": 0,
                "taux_attaque": 0.0,
                "ip_active": "—",
                "derniere_alerte": "—",
            }

        compte = {
            "ROUGE": 0,
            "ORANGE": 0,
            "VERT": 0,
        }

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
            """
            SELECT horodatage
            FROM alertes
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    taux = round(
        100 * (compte["ROUGE"] + compte["ORANGE"]) / total,
        1
    )

    return {
        "total": total,
        "rouge": compte["ROUGE"],
        "orange": compte["ORANGE"],
        "vert": compte["VERT"],
        "taux_attaque": taux,
        "ip_active": ip_row["ip_source"] if ip_row else "—",
        "derniere_alerte": (
            derniere["horodatage"]
            if derniere
            else "—"
        ),
    }


# ============================================================
# ÉVOLUTION TEMPORELLE
# ============================================================

def obtenir_serie_temporelle():

    with obtenir_connexion() as cx:

        lignes = cx.execute(
            """
            SELECT
                strftime(
                    '%Y-%m-%dT%H:%M:00',
                    horodatage
                ) AS minute,
                couleur,
                COUNT(*) AS nombre

            FROM alertes

            GROUP BY minute, couleur

            ORDER BY minute
            """
        ).fetchall()

    return pd.DataFrame(
        [dict(l) for l in lignes],
        columns=[
            "minute",
            "couleur",
            "nombre"
        ]
    )


# ============================================================
# RÉPARTITION DES ATTAQUES
# ============================================================

def obtenir_repartition_attaques():

    with obtenir_connexion() as cx:

        lignes = cx.execute(
            """
            SELECT
                verdict_regle,
                COUNT(*) AS nombre

            FROM alertes

            WHERE verdict_regle != 'NORMAL'

            GROUP BY verdict_regle

            ORDER BY nombre DESC
            """
        ).fetchall()

    return pd.DataFrame(
        [dict(l) for l in lignes],
        columns=[
            "verdict_regle",
            "nombre"
        ]
    )


# ============================================================
# TOP IP
# ============================================================

def obtenir_top_ip(limite=5):

    with obtenir_connexion() as cx:

        lignes = cx.execute(
            """
            SELECT
                ip_source,
                COUNT(*) AS nombre

            FROM alertes

            GROUP BY ip_source

            ORDER BY nombre DESC

            LIMIT ?
            """,
            (limite,)
        ).fetchall()

    return pd.DataFrame(
        [dict(l) for l in lignes],
        columns=[
            "ip_source",
            "nombre"
        ]
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

    return [
        l["verdict_regle"]
        for l in lignes
    ]


# ============================================================
# DERNIÈRES ALERTES
# ============================================================

def obtenir_dernieres_alertes(
    limite=25,
    filtre_couleur=None,
    filtre_type=None
):

    conditions = []
    parametres = []

    if filtre_couleur:

        conditions.append(
            "couleur = ?"
        )

        parametres.append(
            filtre_couleur
        )

    if filtre_type:

        conditions.append(
            "verdict_regle = ?"
        )

        parametres.append(
            filtre_type
        )

    requete = "SELECT * FROM alertes"

    if conditions:

        requete += (
            " WHERE "
            + " AND ".join(conditions)
        )

    requete += (
        " ORDER BY id DESC LIMIT ?"
    )

    with obtenir_connexion() as cx:

        df = pd.read_sql_query(
            requete,
            cx,
            params=parametres + [limite]
        )

    return df


# ============================================================
# RECHERCHE HISTORIQUE
# ============================================================

def rechercher_alertes(
    ip=None,
    couleur=None,
    type_attaque=None,
    date_debut=None,
    date_fin=None,
    page=0,
    taille_page=TAILLE_PAGE_ZONE4
):

    conditions = []
    parametres = []

    if ip:

        conditions.append(
            "(ip_source LIKE ? OR ip_dest LIKE ?)"
        )

        parametres.extend([
            f"%{ip}%",
            f"%{ip}%"
        ])

    if couleur:

        conditions.append(
            "couleur = ?"
        )

        parametres.append(
            couleur
        )

    if type_attaque:

        conditions.append(
            "verdict_regle = ?"
        )

        parametres.append(
            type_attaque
        )

    if date_debut:

        conditions.append(
            "horodatage >= ?"
        )

        parametres.append(
            date_debut
        )

    if date_fin:

        conditions.append(
            "horodatage <= ?"
        )

        parametres.append(
            date_fin + "T23:59:59"
        )

    ou = ""

    if conditions:

        ou = (
            " WHERE "
            + " AND ".join(conditions)
        )

    with obtenir_connexion() as cx:

        total = cx.execute(
            f"""
            SELECT COUNT(*)
            FROM alertes
            {ou}
            """,
            parametres
        ).fetchone()[0]

        df = pd.read_sql_query(
            f"""
            SELECT *
            FROM alertes
            {ou}
            ORDER BY id DESC
            LIMIT ?
            OFFSET ?
            """,
            cx,
            params=parametres + [
                taille_page,
                page * taille_page
            ]
        )

    return df, total


# ============================================================
# CARTE KPI
# ============================================================

def carte_kpi(
    id_carte,
    id_valeur,
    titre,
    couleur_hex
):

    return html.Div(
        id=id_carte,
        n_clicks=0,
        className="carte-kpi",
        style={
            "borderTop":
                f"3px solid {couleur_hex}",
            "color":
                couleur_hex
        },
        children=[

            html.Div(
                "—",
                id=id_valeur,
                className="valeur"
            ),

            html.Div(
                titre,
                className="titre"
            ),
        ]
    )


# ============================================================
# BANDEAU INFORMATIONS
# ============================================================

def bandeau_info(kpis):

    return [

        html.Div(
            className="item",
            children=[

                html.Span(
                    "Taux d'événements suspects "
                    "(rouge+orange)",
                    className="label"
                ),

                html.Span(
                    f"{kpis['taux_attaque']}%",
                    className="valeur"
                ),
            ]
        ),

        html.Div(
            className="item",
            children=[

                html.Span(
                    "IP source la plus active",
                    className="label"
                ),

                html.Span(
                    kpis["ip_active"],
                    className="valeur"
                ),
            ]
        ),

        html.Div(
            className="item",
            children=[

                html.Span(
                    "Dernière alerte",
                    className="label"
                ),

                html.Span(
                    kpis["derniere_alerte"],
                    className="valeur"
                ),
            ]
        ),
    ]


# ============================================================
# GRAPHIQUE ÉVOLUTION TEMPORELLE
# ============================================================

def construire_figure_temporelle(df):

    if df.empty:

        fig = go.Figure()

        fig.update_layout(
            title="Aucune donnée pour le moment"
        )

    else:

        fig = px.bar(
            df,
            x="minute",
            y="nombre",
            color="couleur",
            color_discrete_map=COULEURS,
            title="Évolution des événements dans le temps",
            category_orders={
                "couleur": [
                    "VERT",
                    "ORANGE",
                    "ROUGE"
                ]
            }
        )

        fig.update_traces(
            hovertemplate=(
                "<b>%{x}</b><br>"
                "Niveau : %{fullData.name}<br>"
                "Nombre : %{y}<br>"
                "<extra></extra>"
            )
        )

    fig.update_layout(

        paper_bgcolor=FOND_GRAPHIQUE,
        plot_bgcolor=FOND_GRAPHIQUE,

        font_color=TEXTE_GRAPHIQUE,
        title_font_color=TEXTE_GRAPHIQUE,

        legend_title_text="",

        margin=dict(
            t=55,
            l=15,
            r=15,
            b=55
        ),

        height=380,

        bargap=0.20,

        barmode="stack",

        xaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            title="Temps",
            tickangle=-35,
            type="category",
            rangeslider=dict(
                visible=True
            )
        ),

        yaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            title="Nombre d'événements",
            rangemode="tozero"
        ),
    )

    return fig


# ============================================================
# CAMEMBERT
# ============================================================

def construire_figure_camembert(df):

    if df.empty:

        fig = go.Figure()

        fig.update_layout(
            title="Aucune attaque détectée"
        )

    else:

        types_attaques = (
            df["verdict_regle"]
            .astype(str)
            .tolist()
        )

        couleurs_inconnues = iter(
            COULEURS_ATTAQUES_SUPPLEMENTAIRES
        )

        palette = {}

        for type_attaque in types_attaques:

            if type_attaque in palette:
                continue

            palette[type_attaque] = PALETTE_ATTAQUES.get(
                type_attaque
            )

            if palette[type_attaque] is None:

                palette[type_attaque] = next(
                    couleurs_inconnues,
                    COULEUR_ATTAQUE_DEFAUT
                )

        # Les couleurs sont fournies directement à la trace Plotly.
        # Cela évite que Plotly remplace la palette par son cycle par défaut.
        fig = go.Figure(
            data=[
                go.Pie(
                    labels=types_attaques,
                    values=df["nombre"].tolist(),
                    sort=False,
                    hole=0.48,
                    textinfo="label+percent",
                    textposition="outside",
                    marker=dict(
                        colors=[
                            palette[type_attaque]
                            for type_attaque in types_attaques
                        ],
                        line=dict(
                            color=FOND_GRAPHIQUE,
                            width=3
                        )
                    ),
                    hovertemplate=(
                        "<b>%{label}</b><br>"
                        "Alertes : %{value}<br>"
                        "Part : %{percent}"
                        "<extra></extra>"
                    )
                )
            ]
        )

        fig.update_layout(
            title="Répartition des attaques détectées",
            uniformtext=dict(
                minsize=10,
                mode="hide"
            )
        )

    fig.update_layout(

        paper_bgcolor=FOND_GRAPHIQUE,

        font_color=TEXTE_GRAPHIQUE,

        title_font_color=TEXTE_GRAPHIQUE,

        margin=dict(
            t=55,
            l=10,
            r=10,
            b=10
        ),

        height=380,

        showlegend=True,

        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.02,
            xanchor="center",
            x=0.5,
            font=dict(size=11)
        ),

        uniformtext=dict(
            minsize=10,
            mode="hide"
        ),
    )

    return fig


# ============================================================
# TOP IP
# ============================================================

def construire_figure_top_ip(df):

    if df.empty:

        fig = go.Figure()

        fig.update_layout(
            title="Aucune donnée pour le moment"
        )

    else:

        df = df.sort_values(
            "nombre"
        )

        fig = px.bar(
            df,
            x="nombre",
            y="ip_source",
            orientation="h",
            title="Top 5 des IP sources"
        )

        fig.update_traces(
            marker_color=OCP_BLUE,
            texttemplate="%{x}",
            textposition="outside",
            cliponaxis=False,
            hovertemplate=(
                "<b>%{y}</b><br>"
                "Alertes : %{x}"
                "<extra></extra>"
            )
        )

    fig.update_layout(

        paper_bgcolor=FOND_GRAPHIQUE,
        plot_bgcolor=FOND_GRAPHIQUE,

        font_color=TEXTE_GRAPHIQUE,
        title_font_color=TEXTE_GRAPHIQUE,

        margin=dict(
            t=55,
            l=15,
            r=15,
            b=15
        ),

        height=260,

        xaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            title=""
        ),

        yaxis=dict(
            gridcolor=GRILLE_GRAPHIQUE,
            title="",
            type="category"
        ),

        uniformtext=dict(
            minsize=10,
            mode="hide"
        ),
    )

    return fig


# ============================================================
# PANNEAU DÉTAILS
# ============================================================

def construire_panneau_details(ligne):

    proto_nom = {
        6: "TCP",
        17: "UDP"
    }.get(
        ligne.get("proto"),
        str(ligne.get("proto"))
    )

    items = [

        ("IP destination", ligne.get("ip_dest")),

        ("Port source", ligne.get("port_source")),

        ("Port destination", ligne.get("port_dest")),

        ("Protocole", proto_nom),

        ("Paquets", ligne.get("nb_paquets")),

        ("Octets", ligne.get("nb_octets")),

        ("Durée (s)", ligne.get("duree")),

        (
            "Débit (o/s)",
            round(
                ligne["debit"],
                1
            )
            if ligne.get("debit") is not None
            else "—"
        ),

        (
            "SYN / ACK / FIN / RST",
            f"{ligne.get('syn')} / "
            f"{ligne.get('ack')} / "
            f"{ligne.get('fin')} / "
            f"{ligne.get('rst')}"
        ),

        (
            "Anomalie (Isolation Forest)",
            "Oui"
            if ligne.get("anomalie_if")
            else "Non"
        ),

        (
            "Détail règle",
            ligne.get("detail_regle")
            or "—"
        ),
    ]

    return html.Div(
        className="panneau-details",
        children=[

            html.Div(
                "Détails techniques",
                style={
                    "fontWeight": "600",
                    "marginBottom": "6px",
                    "fontFamily":
                        "Space Grotesk, sans-serif"
                }
            ),

            html.Div(
                className="grille-details",
                children=[

                    html.Div(
                        className="detail-item",
                        children=[

                            html.Div(
                                label,
                                className="label"
                            ),

                            html.Div(
                                str(valeur),
                                className="valeur"
                            )
                        ]
                    )

                    for label, valeur in items
                ]
            ),

            html.Div(
                ligne.get("explication")
                or "Pas d'explication enregistrée.",
                className="explication-box"
            ),
        ]
    )


# ============================================================
# APPLICATION DASH
# ============================================================

app = dash.Dash(
    __name__,
    assets_folder="."
)

app.title = (
    "NIDS Hybride — OCP Group"
)


# ============================================================
# LAYOUT
# ============================================================

app.layout = html.Div(
    className="page",
    children=[

        dcc.Interval(
            id="intervalle-maj",
            interval=3000,
            n_intervals=0
        ),

        dcc.Store(
            id="filtre-actif",
            data={
                "couleur": None,
                "type": None
            }
        ),

        # ====================================================
        # EN-TÊTE
        # ====================================================

        html.Div(
            className="entete",
            children=[

                html.Div(
                    children=[

                        html.H1(
                            "Système de Détection "
                            "d'Intrusion Réseau "
                            "(NIDS) Hybride"
                        ),

                        html.P(
                            "Surveillance en temps réel — "
                            "Règles de signature + "
                            "Intelligence Artificielle"
                        ),
                    ]
                ),

                html.Div(
                    className="statut-direct",
                    children=[

                        html.Div(
                            className="point-pulse"
                        ),

                        html.Span(
                            "EN DIRECT"
                        ),
                    ]
                ),
            ]
        ),

        # ====================================================
        # BANDEAU INFO
        # ====================================================

        html.Div(
            id="bandeau-info",
            className="bandeau-info"
        ),

        # ====================================================
        # KPI
        # ====================================================

        html.Div(
            className="rangee-cartes",
            children=[

                carte_kpi(
                    "carte-total",
                    "valeur-total",
                    "Total des événements",
                    TOTAL_ACCENT
                ),

                carte_kpi(
                    "carte-rouge",
                    "valeur-rouge",
                    "Attaques confirmées",
                    COULEURS["ROUGE"]
                ),

                carte_kpi(
                    "carte-orange",
                    "valeur-orange",
                    "Suspects",
                    COULEURS["ORANGE"]
                ),

                carte_kpi(
                    "carte-vert",
                    "valeur-vert",
                    "Trafic normal",
                    COULEURS["VERT"]
                ),
            ]
        ),

        # ====================================================
        # GRAPHIQUES
        # ====================================================

        html.Div(
            className="zone",
            children=[

                html.Div(
                    className="rangee-graphiques",
                    children=[

                        html.Div(
                            className="panneau",
                            children=[

                                dcc.Graph(
                                    id="graphique-temporel",
                                    config={
                                        "displayModeBar": True,
                                        "scrollZoom": True
                                    }
                                )
                            ]
                        ),

                        html.Div(
                            className="panneau",
                            children=[

                                dcc.Graph(
                                    id="graphique-camembert",
                                    config={
                                        "displayModeBar": False
                                    }
                                )
                            ]
                        ),
                    ]
                ),

                html.Div(
                    className="panneau",
                    children=[

                        dcc.Graph(
                            id="graphique-top-ip",
                            config={
                                "displayModeBar": False
                            }
                        )
                    ]
                ),
            ]
        ),

        # ====================================================
        # FLUX EN DIRECT
        # ====================================================

        html.Div(
            className="zone panneau",
            children=[

                html.Div(
                    className="entete-zone",
                    children=[

                        html.H3(
                            "Flux en direct"
                        ),

                        html.Div(
                            id="badge-filtre-clear",
                            n_clicks=0,
                            className="badge-filtre",
                            style={
                                "display": "none"
                            },
                            children=[

                                html.Span(
                                    id="badge-filtre-texte"
                                ),

                                html.Span(
                                    " ✕"
                                ),
                            ]
                        ),
                    ]
                ),

                dash_table.DataTable(

                    id="table-alertes",

                    columns=[

                        {
                            "name": "Heure",
                            "id": "horodatage"
                        },

                        {
                            "name": "IP source",
                            "id": "ip_source"
                        },

                        {
                            "name": "Service",
                            "id": "service"
                        },

                        {
                            "name": "Règle",
                            "id": "verdict_regle"
                        },

                        {
                            "name": "IA",
                            "id": "verdict_ml"
                        },

                        {
                            "name": "Confiance %",
                            "id": "confiance_ml"
                        },

                        {
                            "name": "Couleur",
                            "id": "couleur"
                        },
                    ],

                    style_as_list_view=True,

                    style_cell={
                        "textAlign": "left",
                        "padding": "10px",
                        "fontFamily":
                            "Inter, sans-serif",
                        "backgroundColor":
                            "var(--bg-panneau)",
                        "color":
                            "var(--texte-principal)",
                        "border": "none",
                        "borderBottom":
                            "1px solid var(--bordure)"
                    },

                    style_header={
                        "backgroundColor":
                            "var(--bg-panneau-clair)",
                        "color":
                            "var(--texte-secondaire)",
                        "fontWeight": "600",
                        "border": "none",
                        "textTransform":
                            "uppercase",
                        "fontSize": "11px"
                    },

                    style_data_conditional=[

                        {
                            "if": {
                                "filter_query":
                                    '{couleur} = "ROUGE"'
                            },
                            "backgroundColor":
                                "rgba(231, 76, 60, 0.18)",
                            "color":
                                "#FF8B82",
                            "borderLeft":
                                "5px solid #E74C3C"
                        },

                        {
                            "if": {
                                "filter_query":
                                    '{couleur} = "ORANGE"'
                            },
                            "backgroundColor":
                                "rgba(243, 156, 18, 0.18)",
                            "color":
                                "#FFC15A",
                            "borderLeft":
                                "5px solid #F39C12"
                        },

                        {
                            "if": {
                                "filter_query":
                                    '{couleur} = "VERT"'
                            },
                            "backgroundColor":
                                "rgba(46, 204, 113, 0.15)",
                            "color":
                                "#67E89A",
                            "borderLeft":
                                "5px solid #2ECC71"
                        },
                    ],

                    page_size=15
                )
            ]
        ),

        # ====================================================
        # HISTORIQUE
        # ====================================================

        html.Div(
            className="zone panneau",
            children=[

                html.H3(
                    "Historique et recherche"
                ),

                html.Div(
                    className="grille-filtres",
                    children=[

                        html.Div(
                            [
                                html.Label(
                                    "IP (source ou destination)"
                                ),

                                dcc.Input(
                                    id="zone4-filtre-ip",
                                    type="text",
                                    placeholder=
                                        "192.168.211...",
                                    style={
                                        "width": "100%"
                                    }
                                )
                            ]
                        ),

                        html.Div(
                            [
                                html.Label(
                                    "Couleur"
                                ),

                                dcc.Dropdown(
                                    id=
                                        "zone4-filtre-couleur",
                                    options=[
                                        {
                                            "label": c,
                                            "value": c
                                        }
                                        for c in [
                                            "VERT",
                                            "ORANGE",
                                            "ROUGE"
                                        ]
                                    ],
                                    placeholder="Toutes"
                                )
                            ]
                        ),

                        html.Div(
                            [
                                html.Label(
                                    "Type d'attaque"
                                ),

                                dcc.Dropdown(
                                    id=
                                        "zone4-filtre-type",
                                    placeholder="Tous"
                                )
                            ]
                        ),

                        html.Div(
                            [
                                html.Label(
                                    "Période"
                                ),

                                dcc.DatePickerRange(
                                    id="zone4-dates",
                                    display_format=
                                        "YYYY-MM-DD"
                                )
                            ]
                        ),
                    ]
                ),

                html.Div(
                    className="rangee-boutons",
                    children=[

                        html.Button(
                            "Rechercher",
                            id=
                                "zone4-bouton-rechercher",
                            n_clicks=0,
                            className=
                                "bouton bouton-primaire"
                        ),

                        html.Button(
                            "Réinitialiser",
                            id=
                                "zone4-bouton-reset",
                            n_clicks=0,
                            className="bouton"
                        ),

                        html.Button(
                            "◀ Précédent",
                            id=
                                "zone4-bouton-precedent",
                            n_clicks=0,
                            className="bouton"
                        ),

                        html.Button(
                            "Suivant ▶",
                            id=
                                "zone4-bouton-suivant",
                            n_clicks=0,
                            className="bouton"
                        ),

                        html.Span(
                            "",
                            id=
                                "zone4-info-pagination",
                            className=
                                "info-pagination"
                        ),
                    ]
                ),

                dash_table.DataTable(

                    id="zone4-table",

                    columns=[

                        {
                            "name": "Heure",
                            "id": "horodatage"
                        },

                        {
                            "name": "IP source",
                            "id": "ip_source"
                        },

                        {
                            "name": "Service",
                            "id": "service"
                        },

                        {
                            "name": "Règle",
                            "id": "verdict_regle"
                        },

                        {
                            "name": "IA",
                            "id": "verdict_ml"
                        },

                        {
                            "name": "Confiance %",
                            "id": "confiance_ml"
                        },

                        {
                            "name": "Couleur",
                            "id": "couleur"
                        },
                    ],

                    style_as_list_view=True,

                    style_cell={
                        "textAlign": "left",
                        "padding": "10px",
                        "fontFamily":
                            "Inter, sans-serif",
                        "backgroundColor":
                            "var(--bg-panneau)",
                        "color":
                            "var(--texte-principal)",
                        "border": "none",
                        "borderBottom":
                            "1px solid var(--bordure)"
                    },

                    style_header={
                        "backgroundColor":
                            "var(--bg-panneau-clair)",
                        "color":
                            "var(--texte-secondaire)",
                        "fontWeight": "600",
                        "border": "none",
                        "textTransform":
                            "uppercase",
                        "fontSize": "11px"
                    },

                    style_data_conditional=[

                        {
                            "if": {
                                "filter_query":
                                    '{couleur} = "ROUGE"'
                            },
                            "backgroundColor":
                                "rgba(231, 76, 60, 0.18)",
                            "color":
                                "#FF8B82",
                            "borderLeft":
                                "5px solid #E74C3C"
                        },

                        {
                            "if": {
                                "filter_query":
                                    '{couleur} = "ORANGE"'
                            },
                            "backgroundColor":
                                "rgba(243, 156, 18, 0.18)",
                            "color":
                                "#FFC15A",
                            "borderLeft":
                                "5px solid #F39C12"
                        },

                        {
                            "if": {
                                "filter_query":
                                    '{couleur} = "VERT"'
                            },
                            "backgroundColor":
                                "rgba(46, 204, 113, 0.15)",
                            "color":
                                "#67E89A",
                            "borderLeft":
                                "5px solid #2ECC71"
                        },
                    ],

                    page_size=TAILLE_PAGE_ZONE4,

                    page_action="none",

                    cell_selectable=True
                ),

                html.Div(
                    id="zone4-details",
                    children=[

                        html.Div(
                            "Clique sur une ligne pour voir "
                            "le détail technique complet "
                            "(paquets, octets, drapeaux TCP, "
                            "anomalie IA, explication).",

                            style={
                                "color":
                                    "var(--texte-secondaire)",
                                "fontSize": "13px",
                                "marginTop": "10px"
                            }
                        )
                    ]
                )
            ]
        ),
    ]
)


# ============================================================
# CALLBACK — MISE À JOUR GLOBALE
# ============================================================

@app.callback(

    Output(
        "valeur-total",
        "children"
    ),

    Output(
        "valeur-rouge",
        "children"
    ),

    Output(
        "valeur-orange",
        "children"
    ),

    Output(
        "valeur-vert",
        "children"
    ),

    Output(
        "bandeau-info",
        "children"
    ),

    Output(
        "graphique-temporel",
        "figure"
    ),

    Output(
        "graphique-camembert",
        "figure"
    ),

    Output(
        "graphique-top-ip",
        "figure"
    ),

    Output(
        "zone4-filtre-type",
        "options"
    ),

    Input(
        "intervalle-maj",
        "n_intervals"
    )
)
def maj_globale(n):

    kpis = obtenir_kpis()

    fig_temporel = (
        construire_figure_temporelle(
            obtenir_serie_temporelle()
        )
    )

    fig_camembert = (
        construire_figure_camembert(
            obtenir_repartition_attaques()
        )
    )

    fig_top_ip = (
        construire_figure_top_ip(
            obtenir_top_ip()
        )
    )

    types_dispo = (
        obtenir_types_attaques()
    )

    return (

        kpis["total"],

        kpis["rouge"],

        kpis["orange"],

        kpis["vert"],

        bandeau_info(kpis),

        fig_temporel,

        fig_camembert,

        fig_top_ip,

        [
            {
                "label": t,
                "value": t
            }
            for t in types_dispo
        ]
    )


# ============================================================
# CALLBACK — TABLE FLUX DIRECT
# ============================================================

@app.callback(

    Output(
        "table-alertes",
        "data"
    ),

    Input(
        "intervalle-maj",
        "n_intervals"
    ),

    Input(
        "filtre-actif",
        "data"
    )
)
def maj_table_zone3(
    n,
    filtre
):

    filtre = filtre or {}

    df = obtenir_dernieres_alertes(

        limite=25,

        filtre_couleur=
            filtre.get("couleur"),

        filtre_type=
            filtre.get("type")
    )

    if df.empty:
        return []

    df["service"] = (
        df["port_dest"]
        .apply(nom_service)
    )

    df["confiance_ml"] = (
        df["confiance_ml"]
        .round(1)
    )

    colonnes = [

        "horodatage",

        "ip_source",

        "service",

        "verdict_regle",

        "verdict_ml",

        "confiance_ml",

        "couleur"
    ]

    return df[colonnes].to_dict(
        "records"
    )


# ============================================================
# CALLBACK — FILTRES
# ============================================================

@app.callback(

    Output(
        "filtre-actif",
        "data"
    ),

    Output(
        "carte-rouge",
        "className"
    ),

    Output(
        "carte-orange",
        "className"
    ),

    Output(
        "carte-vert",
        "className"
    ),

    Output(
        "badge-filtre-clear",
        "style"
    ),

    Output(
        "badge-filtre-texte",
        "children"
    ),

    Input(
        "carte-total",
        "n_clicks"
    ),

    Input(
        "carte-rouge",
        "n_clicks"
    ),

    Input(
        "carte-orange",
        "n_clicks"
    ),

    Input(
        "carte-vert",
        "n_clicks"
    ),

    Input(
        "graphique-camembert",
        "clickData"
    ),

    Input(
        "badge-filtre-clear",
        "n_clicks"
    ),

    State(
        "filtre-actif",
        "data"
    ),

    prevent_initial_call=True
)
def gerer_clic_filtre(

    n_total,
    n_rouge,
    n_orange,
    n_vert,
    click_camembert,
    n_clear,
    filtre_actuel
):

    declencheur = ctx.triggered_id

    filtre_actuel = (
        filtre_actuel
        or {
            "couleur": None,
            "type": None
        }
    )

    nouveau_filtre = dict(
        filtre_actuel
    )

    if declencheur in (
        "carte-total",
        "badge-filtre-clear"
    ):

        nouveau_filtre = {
            "couleur": None,
            "type": None
        }

    elif declencheur in (
        "carte-rouge",
        "carte-orange",
        "carte-vert"
    ):

        couleur_visee = (
            declencheur
            .replace(
                "carte-",
                ""
            )
            .upper()
        )

        if (
            filtre_actuel.get(
                "couleur"
            )
            == couleur_visee
        ):

            nouveau_filtre = {
                "couleur": None,
                "type": None
            }

        else:

            nouveau_filtre = {
                "couleur": couleur_visee,
                "type": None
            }

    elif (
        declencheur
        == "graphique-camembert"
        and click_camembert
    ):

        type_vise = (
            click_camembert[
                "points"
            ][0]["label"]
        )

        if (
            filtre_actuel.get("type")
            == type_vise
        ):

            nouveau_filtre = {
                "couleur": None,
                "type": None
            }

        else:

            nouveau_filtre = {
                "couleur": None,
                "type": type_vise
            }

    def cls(cle):

        if (
            nouveau_filtre.get(
                "couleur"
            )
            == cle
        ):
            return "carte-kpi actif"

        return "carte-kpi"

    actif = bool(

        nouveau_filtre.get(
            "couleur"
        )

        or

        nouveau_filtre.get(
            "type"
        )
    )

    style_badge = (

        {"display": "inline-flex"}
        if actif
        else
        {"display": "none"}
    )

    texte_badge = (
        "Filtre : "
        +
        (
            nouveau_filtre.get(
                "couleur"
            )
            or
            nouveau_filtre.get(
                "type"
            )
            or
            ""
        )
    )

    return (

        nouveau_filtre,

        cls("ROUGE"),

        cls("ORANGE"),

        cls("VERT"),

        style_badge,

        texte_badge
    )


# ============================================================
# CALLBACK — HISTORIQUE
# ============================================================

@app.callback(

    Output(
        "zone4-table",
        "data"
    ),

    Output(
        "zone4-info-pagination",
        "children"
    ),

    Output(
        "zone4-table",
        "active_cell"
    ),

    Output(
        "zone4-filtre-ip",
        "value"
    ),

    Output(
        "zone4-filtre-couleur",
        "value"
    ),

    Output(
        "zone4-filtre-type",
        "value"
    ),

    Output(
        "zone4-dates",
        "start_date"
    ),

    Output(
        "zone4-dates",
        "end_date"
    ),

    Input(
        "zone4-bouton-rechercher",
        "n_clicks"
    ),

    Input(
        "zone4-bouton-reset",
        "n_clicks"
    ),

    Input(
        "zone4-bouton-precedent",
        "n_clicks"
    ),

    Input(
        "zone4-bouton-suivant",
        "n_clicks"
    ),

    State(
        "zone4-filtre-ip",
        "value"
    ),

    State(
        "zone4-filtre-couleur",
        "value"
    ),

    State(
        "zone4-filtre-type",
        "value"
    ),

    State(
        "zone4-dates",
        "start_date"
    ),

    State(
        "zone4-dates",
        "end_date"
    ),

    State(
        "zone4-info-pagination",
        "children"
    ),

    prevent_initial_call=True
)
def gerer_recherche_zone4(

    n_rech,
    n_reset,
    n_prec,
    n_suiv,

    ip,
    couleur,
    type_attaque,

    date_debut,
    date_fin,

    info_actuelle
):

    declencheur = ctx.triggered_id

    page_actuelle = 0

    if (
        info_actuelle
        and "Page " in info_actuelle
    ):

        try:

            page_actuelle = int(
                info_actuelle
                .split("Page ")[1]
                .split(" /")[0]
            ) - 1

        except (
            ValueError,
            IndexError
        ):

            page_actuelle = 0

    champs_reset = (
        no_update,
        no_update,
        no_update,
        no_update,
        no_update
    )

    page = page_actuelle

    if (
        declencheur
        == "zone4-bouton-reset"
    ):

        ip = None
        couleur = None
        type_attaque = None
        date_debut = None
        date_fin = None

        page = 0

        champs_reset = (
            None,
            None,
            None,
            None,
            None
        )

    elif (
        declencheur
        == "zone4-bouton-rechercher"
    ):

        page = 0

    elif (
        declencheur
        == "zone4-bouton-precedent"
    ):

        page = max(
            0,
            page_actuelle - 1
        )

    elif (
        declencheur
        == "zone4-bouton-suivant"
    ):

        page = page_actuelle + 1

    df, total = rechercher_alertes(

        ip=ip,

        couleur=couleur,

        type_attaque=
            type_attaque,

        date_debut=
            date_debut,

        date_fin=
            date_fin,

        page=page
    )

    nb_pages = (

        max(
            1,
            -(
                -total
                // TAILLE_PAGE_ZONE4
            )
        )

        if total

        else 1
    )

    info = (
        f"Page {page + 1} / "
        f"{nb_pages} — "
        f"{total} résultat(s)"
    )

    if not df.empty:

        df["service"] = (
            df["port_dest"]
            .apply(nom_service)
        )

        df["confiance_ml"] = (
            df["confiance_ml"]
            .round(1)
        )

    colonnes = [

        "horodatage",

        "ip_source",

        "service",

        "verdict_regle",

        "verdict_ml",

        "confiance_ml",

        "couleur"
    ]

    donnees_table = (

        df[colonnes].to_dict(
            "records"
        )

        if not df.empty

        else []
    )

    return (

        donnees_table,

        info,

        None

    ) + champs_reset


# ============================================================
# CALLBACK — DÉTAILS
# ============================================================

@app.callback(

    Output(
        "zone4-details",
        "children"
    ),

    Input(
        "zone4-table",
        "active_cell"
    ),

    State(
        "zone4-table",
        "data"
    ),

    prevent_initial_call=True
)
def afficher_details_zone4(

    cellule_active,
    donnees
):

    if (
        not cellule_active
        or not donnees
    ):

        return [

            html.Div(
                "Clique sur une ligne pour "
                "voir le détail technique complet "
                "(paquets, octets, drapeaux TCP, "
                "anomalie IA, explication).",

                style={
                    "color":
                        "var(--texte-secondaire)",
                    "fontSize": "13px",
                    "marginTop": "10px"
                }
            )
        ]

    ligne = donnees[
        cellule_active["row"]
    ]

    # La table n'a pas toutes les colonnes
    # nécessaires aux détails.
    # On récupère la vraie ligne depuis SQLite.

    try:

        with obtenir_connexion() as cx:

            row = cx.execute(
                """
                SELECT *
                FROM alertes
                WHERE horodatage = ?
                  AND ip_source = ?
                  AND verdict_regle = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    ligne["horodatage"],
                    ligne["ip_source"],
                    ligne["verdict_regle"]
                )
            ).fetchone()

        if row:

            ligne_complete = dict(row)

        else:

            ligne_complete = ligne

    except Exception:

        ligne_complete = ligne

    return construire_panneau_details(
        ligne_complete
    )


# ============================================================
# LANCEMENT
# ============================================================

if __name__ == "__main__":

    print(
        "Tableau de bord démarré : "
        "http://localhost:8050"
    )

    app.run(
        host="0.0.0.0",
        port=8050,
        debug=False
    )