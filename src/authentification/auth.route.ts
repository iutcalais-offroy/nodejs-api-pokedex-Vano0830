import {NextFunction ,Request, Response, Router} from 'express'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import {prisma} from "../database";
import {env} from '../env';


export const authRouter = Router()

// POST /auth/login
// Accessible via POST /auth/login

authRouter.post('/sign-up', async (req: Request, res: Response) => {
  const { email, password, username } = req.body

  try {
    // 1. Vérifier les champs
    if (!email || !password || !username) {
      return res.status(400).json({
        error: 'Tous les champs sont requis',
      })
    }

    // 2. Vérifier si l'utilisateur existe déjà
    const existingUser = await prisma.user.findUnique({
      where: { email },
    })

    if (existingUser) {
      return res.status(400).json({
        error: 'Cet email est déjà utilisé',
      })
    }

    // 3. Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10)

    // 4. Créer l'utilisateur
    const user = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword,
      },
    })

    // 5. Générer le JWT
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
      },
      process.env.JWT_SECRET as string,
      { expiresIn: '7d' }
    )

    // 6. Réponse
    return res.status(201).json({
      message: 'Inscription réussie',
      token,
      user: {
        id: user.id,
        name: user.username,
        email: user.email,
      },
    })
  } catch (error) {
    console.error('Erreur lors de l’inscription :', error)
    return res.status(500).json({
      error: 'Erreur serveur',
    })
  }
})


authRouter.post('/sign-in', async (req: Request, res: Response) => {
    const {email, password} = req.body

    try {
        // 1. Vérifier que l'utilisateur existe
        const user = await prisma.user.findUnique({
            where: {email},
        })

        if (!user) {
            return res.status(401).json({error: 'Email ou mot de passe incorrect'})
        }

        // 2. Vérifier le mot de passe
        const isPasswordValid = await bcrypt.compare(password, user.password)

        if (!isPasswordValid) {
            return res.status(401).json({error: 'Email ou mot de passe incorrect'})
        }

        // 3. Générer le JWT
        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
            },
            process.env.JWT_SECRET as string,
            {expiresIn: '7d'}, // Le token expire dans 7 jour
        )

        // 4. Retourner les info 
        return res.status(200).json({
            message: 'Inscription reusssi',
            token,
            user: {
                id: user.id,
                name: user.username,
                email: user.email,
            },
        })
    } catch (error) {
        console.error('Erreur lors de la connexion:', error)
        return res.status(500).json({error: 'Erreur serveur'})
    }
})
    
// Étendre le type Request pour ajouter userId
    declare global {
        namespace Express {
            interface Request {
                userId?: number
            }
        }
    }

    export const authenticateToken = (
    req: Request,
    res: Response,
     next: NextFunction
    ) => {

    // 1. Récupérer le token depuis l'en-tête Authorization
    const authHeader = req.headers.authorization
    const token = authHeader?.split(' ')[1] 

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' })
    }

    try {
        // 2. Vérifier et décoder le token
        const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET as string
        ) as {
        userId: number
        email: string
        }

        // 3. Ajouter userId à la requête pour l'utiliser dans les routes
        req.user = {
        userId: decoded.userId,
        email: decoded.email,
        }

        // 4. Passer au prochain middleware ou à la route
        next()
    } catch (error) {
        return res.status(401).json({
        error: 'Token invalide ou expiré',
        })
    }
    }

export default authRouter